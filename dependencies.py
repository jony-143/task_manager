"""
Dependency injection functions for database sessions, authentication,
and authorization.

This module implements FastAPI's dependency-injection system to enforce
access control and provide reusable resources (database sessions).
Dependencies are chained to form a "dependency tree" where higher-level
dependencies (like get_admin_user) depend on lower-level ones (like
get_current_user).

Design decisions:
- Dependencies are used to enforce authentication and authorization at the
  endpoint layer.
- Chaining dependencies (get_current_active_user depends on
  get_current_user) allows granular permission levels without code
  duplication and no duplicated checks.
- SessionLocal() database sessions use rollback-on-error to prevent
  partial updates and stale connection state.
- TokenPayload strict validation (with extra="forbid") and "require" option in 
  JWT decoding reject tokens with unexpected or missing fields, hardening 
  against token-tampering attacks.
- Object-level authorization: endpoints check resource ownership
  separately, returning 404 for unauthorized access to avoid leaking
  whether a resource exists.
"""

from typing import Annotated

from pydantic import ValidationError
import jwt
from jwt.exceptions import InvalidTokenError
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status

from crud import get_user_by_username
from config import settings
from database import SessionLocal
from security import TokenPayload, oauth2_scheme, verify_password
from models import User
from schemas import PasswordConfirmation


def get_db():
    """
    Provide a database session for each request.

    Yields a SQLAlchemy Session for the duration of a request.
    Automatically rolls back on exceptions to prevent partial
    updates and closes the session when the request completes.
    Doesn't commit the transaction; committing is the responsibility 
    of the caller.
    Used as a dependency to inject db into route handlers.

    Yields:
        A SQLAlchemy Session connected to the application database.

    Design rationale:
    - This dependency does not commit the transaction: each endpoint is 
      responsible for committing changes to the database and avoiding partial 
      and inconsistent updates. This avoids unexpected commits and
      changes in the database, giving a more robust design.
    - Rollback-on-exception ensures that if a request handler raises
      an error after database writes, those writes are rolled back,
      leaving the database consistent.
    - Close-in-finally ensures the session is never held open after
      the request, preventing connection exhaustion.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


SessionDep = Annotated[Session, Depends(get_db)]
TokenDep = Annotated[str, Depends(oauth2_scheme)]


def get_current_user(db: SessionDep, token: TokenDep) -> User:
    """
    Retrieve and authenticate the current user from a JWT token.

    Decodes the JWT token, validates its claims (sub, exp), and looks
    up the corresponding User from the database. If any step fails
    (invalid token, expired, user not found), raises a 401
    Unauthorized exception.

    Args:
        db: Database session dependency.
        token: JWT token from Authorization header (provided by
               OAuth2PasswordBearer).

    Returns:
        The User ORM object corresponding to the token's 'sub'
        (username) claim.

    Raises:
        HTTPException (401 Unauthorized): If the token is invalid,
                                          expired, missing required
                                          claims, has an invalid
                                          signature, or the user no
                                          longer exists in the
                                          database.

    Design decisions:
    - All errors returns a 401 Unauthorized, ensuring clients cannot 
      distinguish between invalid tokens and non-existent users.
    - Decodes the token with options={"require": ["exp", "sub"],
      "verify_exp": True}:
      * require: ensures both 'sub' and 'exp' claims are present.
      * verify_exp: PyJWT raises an error if exp < now, preventing
        use of stale tokens.
    - Algorithm specified in settings.ALGORITHM is used for token decoding. 
      This avoids potential security issues from using the token's algorithm 
      header.
    - Looks up the user from the database (doesn't trust token data
      alone).
    - Returns the User object; higher-level dependencies use this to
      check is_active, is_admin, etc; and it gives the endpoints access to
      the database avoiding repetitive queries.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            jwt=token,
            key=settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "sub"], "verify_exp": True},
        )
        token_data = TokenPayload(**payload)
    except (InvalidTokenError, ValidationError):
        raise credentials_exception
    user = get_user_by_username(db=db, username=token_data.sub)
    if not user:
        raise credentials_exception
    return user


def get_current_active_user(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """
    Retrieve the current user and ensure they are active.

    Wraps get_current_user() and adds a check: if user.is_active is
    False, raises 403 Forbidden. Used to restrict endpoints to active
    users (soft-delete implementation).

    Args:
        user: Injected by get_current_user dependency.

    Returns:
        The User ORM object if is_active is True.

    Raises:
        HTTPException (403 Forbidden): If user.is_active is False.

    Design decisions:
    - Separating this check from get_current_user allows endpoints to access 
      inactive users.
    - All role and permition checks are done against the database. This ensures
      that changes to user roles or permissions are immediately effective.
    - Is_active enforcement at the dependency level prevents
      accidental bypasses by forgetting a check in a route handler.
    """
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    return user


def get_admin_user(
    user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """
    Retrieve the current user and ensure they have admin privileges.

    Chains get_current_active_user (which ensures the user is both
    authenticated and active), then adds a role check: if
    user.is_admin is False, raises 403 Forbidden. Attached to
    admin-only endpoints.

    Args:
        user: Injected by get_current_active_user dependency. Already
              guaranteed to be authenticated and active.

    Returns:
        The User ORM object if is_admin is True.

    Raises:
        HTTPException (403 Forbidden): If user.is_admin is False.

    Design decisions:
    - Chaining dependencies (admin depends on active, active depends
      on current) avoids duplicating token-validation logic. Admin
      endpoints get all checks: valid token, user exists, is_active,
      is_admin.
    - All role and permition checks are done against the database. This ensures
      that changes to user roles or permissions are immediately effective.
    - Role-based access control (RBAC) is centralized here: if admin
      routes need new checks, only this function changes.
    """
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges",
        )
    return user


UserDep = Annotated[User, Depends(get_current_active_user)]
AdminDep = Annotated[User, Depends(get_admin_user)]


def verify_current_password(
    password_confirmation: PasswordConfirmation,
    user: UserDep,
) -> User:
    """
    Verify that the user's provided password matches their stored hash.

    Used to re-authenticate users before sensitive operations (e.g.,
    deleting their own account). Compares the plaintext password from
    PasswordConfirmation schema against user.password_hash using
    Argon2 verification.

    Args:
        password_confirmation: Pydantic schema with 'password' field
                               from request body.
        user: Injected by UserDep (get_current_active_user dependency).

    Returns:
        The User ORM object if the password is correct.

    Raises:
        HTTPException (401 Unauthorized): If the provided password does
                                          not match the user's stored
                                          hash.

    Design rationale:
    - Requires users to re-enter their password for destructive
      operations (account deletion). This mitigates session-hijacking 
      risks: an attacker with a valid token still cannot delete the 
      account without the plaintext password.
    - Used as a dependency in the DELETE /users/me route. The route
      handler receives the same user object returned by this
      dependency, confirming password validation.
    - Returns the User object (not just bool) to allow use as a
      dependency yielding a typed value to downstream code.
    """
    valid, _ = verify_password(
        password_confirmation.password,
        user.password_hash,
    )
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


ReauthDep = Annotated[User, Depends(verify_current_password)]
