from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from config import settings
from dependencies import AdminDep, SessionDep, get_admin_user
import crud
from schemas import UserOut, TaskOut, UserAdminUpdate, UserOutAdmin
from models import User

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    include_in_schema=True,
    dependencies=[Depends(get_admin_user)],
)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    admin_user: AdminDep,
    db: SessionDep,
) -> None:
    user = crud.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    if user.id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin user cannot delete themselves",
        )
    crud.delete_user(db=db, user=user)
    return None


@router.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task_admin(
    task_id: int,
    db: SessionDep,
) -> None:
    task = crud.get_task_by_id(db=db, task_id=task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    crud.delete_task(db=db, task=task)
    return None


@router.get("/users", response_model=list[UserOutAdmin])
def get_all_users(
    db: SessionDep,
    limit: Annotated[int, Query(
        ge=1, le=settings.USER_MAX_LIMIT)] = settings.USER_DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, le=settings.MAX_OFFSET)] = 0,
) -> list[User]:
    users = crud.get_all_users(db=db, limit=limit, offset=offset)
    return users


@router.get("/tasks", response_model=list[TaskOut])
def get_all_tasks(
    db: SessionDep,
    limit: Annotated[int, Query(
        ge=1, le=settings.TASK_MAX_LIMIT)] = settings.TASK_DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, le=settings.MAX_OFFSET)] = 0,
) -> Any:
    tasks = crud.get_all_tasks(db=db, limit=limit, offset=offset)
    return tasks


@router.patch("/users/{user_id}", response_model=UserOutAdmin)
def update_user_permissions(
    user_id: int,
    user_update: UserAdminUpdate,
    admin_user: AdminDep,
    db: SessionDep,
) -> User:
    if user_id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin user cannot update their own permissions",
        )
    user = crud.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    user = crud.update_user(db=db, user=user, user_update=user_update)
    return user
