"""
JWT token creation, password hashing, and authentication utilities.

This module handles all security-sensitive operations:
- Password hashing/verification using Argon2 (resistant to GPU/ASIC
  attacks)
- JWT token generation with expiration claims
- OAuth2 Bearer token extraction from requests

Design decisions:
- Timing-attack mitigation: DUMMY_HASH allows checking a hash even
  when user doesn't exist, so both "user not found" and "wrong
  password" paths take similar time, reducing information leakage.
- JWT includes both 'sub' (subject: username) and 'exp' (expiration)
  claims with strict validation in dependencies.py.
- TokenPayload uses extra="forbid" to reject tokens with unexpected
  fields, hardening against token tampering or future vulnerabilities.
- pwdlib supports hasher migration, and this module is prepared for that. The
  variable password_hash of this module can have multiple hashers for this 
  propuse, being the first argument the most recent hasher. verify_password()
  function will then return an updated hash if rehashing is needed.
"""

from datetime import datetime, timedelta, timezone

import secrets
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
import jwt
from pydantic import BaseModel, ConfigDict
from fastapi.security import OAuth2PasswordBearer

from config import settings


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


class TokenPayload(BaseModel):
    """
    JWT token payload schema for access tokens.

    This schema validates the structure of decoded JWT tokens. It
    enforces that tokens contain exactly the required claims and no
    extra fields, hardening against token-tampering attacks.

    Attributes:
        sub: Subject claim; contains the username identifying the
             authenticated user.
        exp: Expiration timestamp (seconds since Unix epoch). Used by
             PyJWT to validate token freshness; expired tokens are
             rejected.

    Design decisions:
    - extra="forbid" (ConfigDict) rejects tokens with unexpected
      fields. This catches malformed or tampered tokens early and
      prevents future vulnerabilities if new claims are added without
      updating validation logic.
    - Only includes 'sub' and 'exp', not user_id or is_admin: keeps
      tokens minimal and forces the dependencies layer to look up the
      user from the database on each request (justification: ensures
      we always check user.is_active, even if admin status changes
      between token issuance and use).
    - PyJWT's decode() with options={"require": ["exp", "sub"],
      "verify_exp": True} (in dependencies.py) validates both claims
      exist and that expiration is fresh.
    """

    model_config = ConfigDict(extra="forbid")

    sub: str
    exp: int


password_hash = PasswordHash(
    (
        Argon2Hasher(),
    )
)

DUMMY_HASH = password_hash.hash(secrets.token_hex(32))


def create_access_token(
    subject: str,
    expires_delta: timedelta = timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    ),
) -> str:
    """
    Create a signed JWT access token.

    Generates a JWT containing the user's username (sub claim) and an
    expiration time (exp claim). The token is signed with the
    application's SECRET_KEY and the algorithm HS256 and can be verified by 
    any service that knows the secret.

    Args:
        subject: The username to encode in the 'sub' claim. This
                 identifies which user owns this token.
        expires_delta: How long the token is valid for (default: from
                       settings). Added to the current UTC time to
                       compute the exp claim.

    Returns:
        A signed JWT string (e.g., 'eyJhbGciOiJIUzI1NiI...'). The
        client includes this in the Authorization header as
        "Bearer <token>" for subsequent requests.

    Design rationale:
    - Encodes username, not user_id: usernames are more human-readable
      and stable (IDs can be reused after deletion if not careful;
      usernames are unique).
    - Expires based on settings.ACCESS_TOKEN_EXPIRE_MINUTES to enforce
      re-authentication.
    - Uses current UTC time (timezone-aware) for consistency across
      timezones.
    """
    expire = datetime.now(timezone.utc) + expires_delta
    encoded_jwt = jwt.encode(
        payload={"sub": subject, "exp": expire},
        key=settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return encoded_jwt


def verify_password(
    plain_password: str, hashed_password: str
) -> tuple[bool, str | None]:
    """
    Verify a plaintext password against an Argon2 hash.

    Uses pwdlib's Argon2 hasher with timing-resistant comparison to
    mitigate timing-attack vulnerabilities. Will also return an updated
    hash if the password needs rehashing (in case parameters or algorithm 
    changed).

    Args:
        plain_password: The user-provided plaintext password.
        hashed_password: The stored Argon2 hash to compare against.

    Returns:
        A tuple (valid, updated_hash):
        - valid (bool): True if the password matches the hash, False
          otherwise. If the hashed password is outdated, valid is still True
          and updated_hash will be returned.
        - updated_hash (str | None): A newly-hashed password if parameters
          or algorithms have changed. If None, no rehashing needed.

    Design decisions:
    - Returns a tuple (not just bool) to allow automatic password hash
      upgrades when Argon2 parameters or algorithm change. The authenticate()
      function in crud.py checks for updated_hash and re-saves it if
      present.
    - Argon2's timing-resistant verification reduces information leakage
      compared to naive string comparison (== operator).
    - Called even when user doesn't exist (with DUMMY_HASH) to maintain
      consistent timing between "user not found" and "wrong password"
      error paths.
    """
    return password_hash.verify_and_update(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a plaintext password using Argon2.

    Wrapper around pwdlib's password_hash.hash(). Used during user
    registration to store passwords securely; never persists plaintext
    passwords.

    Args:
        password: The plaintext password to hash. Assumed to have been
                  validated for length/complexity by Pydantic schema
                  (UserCreate).

    Returns:
        An Argon2 hash string suitable for storage in the
        password_hash column.

    Design decisions:
    - Deterministic output for the same password (not randomized like
      bcrypt), but Argon2 internally uses random salt; different calls
      produce different hashes even for the same plaintext password.
    """
    return password_hash.hash(password)
