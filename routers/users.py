from fastapi import APIRouter, HTTPException, status
from sqlalchemy.exc import IntegrityError

from dependencies import SessionDep, UserDep, ReauthDep
from schemas import UserCreate, UserOut
from models import User
import crud

router = APIRouter(
    prefix="/users",
    tags=["users"],
)


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserOut,
)
def register_user(user_in: UserCreate, db: SessionDep) -> User:
    credentials_taken_exception = HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="A user with those credentials already exists",
    )
    if crud.get_user_by_email(db=db, email=user_in.email):
        raise credentials_taken_exception

    if crud.get_user_by_username(db=db, username=user_in.username):
        raise credentials_taken_exception

    try:
        return crud.create_user(db=db, user_in=user_in)
    except IntegrityError as exc:
        db.rollback()
        raise credentials_taken_exception from exc


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user: ReauthDep,
    db: SessionDep,
) -> None:
    crud.delete_user(db=db, user=user)
    return None
