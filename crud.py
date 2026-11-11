from sqlalchemy import select
from sqlalchemy.orm import Session

from models import User, Task
from schemas import TaskCreate, TaskUpdate, UserCreate, UserAdminUpdate
from security import get_password_hash, verify_password, DUMMY_HASH

_DEFAULT_LIMIT_USERS = 100
_DEFAULT_LIMIT_TASKS = 100

# USERS


def authenticate(*, db: Session, email: str, password: str) -> User | None:
    db_user = get_user_by_email(db=db, email=email)
    if not db_user:
        _ = verify_password(password, DUMMY_HASH)
        return None
    valid, updated_hash = verify_password(password, db_user.password_hash)
    if not valid:
        return None
    if updated_hash:
        db_user.password_hash = updated_hash
        db.commit()
        db.refresh(db_user)
    return db_user


def get_user_by_id(*, db: Session, user_id: int) -> User | None:
    return db.get(User, user_id)


def get_user_by_username(*, db: Session, username: str) -> User | None:
    stmt = select(User).where(User.username == username)
    return db.scalars(stmt).first()


def get_user_by_email(*, db: Session, email: str) -> User | None:
    stmt = select(User).where(User.email == email)
    return db.scalars(stmt).first()


def get_all_users(
    *, db: Session, limit: int = _DEFAULT_LIMIT_USERS, offset: int = 0
) -> list[User]:
    stmt = select(User).order_by(User.id).limit(limit).offset(offset)
    return list(db.scalars(stmt).all())


def create_user(*, db: Session, user_in: UserCreate) -> User:
    db_user = User(
        username=user_in.username,
        email=user_in.email,
        password_hash=get_password_hash(user_in.password),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user(*, db: Session, user: User, user_update: UserAdminUpdate) -> User:
    for field, value in user_update.model_dump(exclude_unset=True).items():
        setattr(user, field, value)
    db.commit()
    db.refresh(user)
    return user


def delete_user(*, db: Session, user: User) -> None:
    db.delete(user)
    db.commit()


# TASKS

def get_task_by_id(*, db: Session, task_id: int) -> Task | None:
    return db.get(Task, task_id)


def get_tasks_by_user(
    *, db: Session, user: User, limit: int = _DEFAULT_LIMIT_TASKS, offset: int = 0
) -> list[Task]:
    stmt = (
        select(Task)
        .where(Task.user_id == user.id)
        .order_by(Task.id)
        .limit(limit)
        .offset(offset)
    )
    return list(db.scalars(stmt).all())


def get_all_tasks(
    *, db: Session, limit: int = _DEFAULT_LIMIT_TASKS, offset: int = 0
) -> list[Task]:
    stmt = select(Task).order_by(Task.id).limit(limit).offset(offset)
    return list(db.scalars(stmt).all())


def create_task(*, db: Session, user_id: int, task_in: TaskCreate) -> Task:
    db_task = Task(
        user_id=user_id,
        **task_in.model_dump(),
    )
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task


def update_task(*, db: Session, task: Task, task_in: TaskUpdate) -> Task:
    for field, value in task_in.model_dump(exclude_unset=True).items():
        setattr(task, field, value)
    db.commit()
    db.refresh(task)
    return task


def delete_task(*, db: Session, task: Task) -> None:
    db.delete(task)
    db.commit()


# def mark_completed_task(db: Session, task: Task) -> Task:
#    task.completed = True
#    db.commit()
#    return task
