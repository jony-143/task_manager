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
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    return user


def get_admin_user(
    user: Annotated[User, Depends(get_current_active_user)],
) -> User:
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
