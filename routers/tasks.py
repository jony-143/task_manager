from typing import Annotated

from fastapi import APIRouter, HTTPException, Depends, Query, status

from dependencies import SessionDep, UserDep, get_current_active_user
from models import Task
from schemas import TaskCreate, TaskUpdate, TaskOut
import crud
from config import settings


router = APIRouter(
    prefix="/tasks",
    tags=["tasks"],
    dependencies=[Depends(get_current_active_user)],
)


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=TaskOut,
)
def create_task(task_in: TaskCreate, user: UserDep, db: SessionDep) -> Task:
    return crud.create_task(db=db, user_id=user.id, task_in=task_in)


@router.get("/", response_model=list[TaskOut])
def list_tasks(
    user: UserDep,
    db: SessionDep,
    limit: Annotated[int, Query(
        ge=1, le=settings.TASK_MAX_LIMIT)] = settings.TASK_DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, le=settings.MAX_OFFSET)] = 0,
) -> list[Task]:
    return crud.get_tasks_by_user(db=db, user=user, limit=limit, offset=offset)


@router.get("/{task_id}", response_model=TaskOut)
def get_task(task_id: int, user: UserDep, db: SessionDep) -> Task:
    not_found_exception = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Task not found",
    )
    task = crud.get_task_by_id(db=db, task_id=task_id)
    if not task:
        raise not_found_exception
    if task.user_id != user.id:
        raise not_found_exception
    return task


@router.patch("/{task_id}", response_model=TaskOut)
def update_task(
    task_id: int,
    task_in: TaskUpdate,
    user: UserDep,
    db: SessionDep,
) -> Task:
    not_found_exception = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Task not found",
    )
    task = crud.get_task_by_id(db=db, task_id=task_id)

    if not task:
        raise not_found_exception
    if task.user_id != user.id:
        raise not_found_exception

    return crud.update_task(db=db, task=task, task_in=task_in)


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(task_id: int, user: UserDep, db: SessionDep) -> None:
    not_found_exception = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Task not found",
    )
    task = crud.get_task_by_id(db=db, task_id=task_id)
    if not task:
        raise not_found_exception
    if task.user_id != user.id:
        raise not_found_exception
    crud.delete_task(db=db, task=task)
    return None
