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
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
) -> str:
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
    return password_hash.verify_and_update(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return password_hash.hash(password)
