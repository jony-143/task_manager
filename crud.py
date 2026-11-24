"""
CRUD (Create, Read, Update, Delete) operations for User and Task
entities.

This module centralizes database operations, acting as a data-access
layer (DAO-like). All database queries go through here, not directly
in route handlers. This provides a single place to review database
safety (SQL injection, N+1 queries) and simplifies testing (mock this
layer, not the database). This module uses SQLAlchemy ORM for all database 
interactions.

Design decisions:
- SQLAlchemy's select() with bound parameters prevents SQL injection by
  default.
- authenticate() implements timing-attack mitigation: checks password
  hash even if user doesn't exist (using DUMMY_HASH), so both "user not
  found" and "wrong password" paths take similar time.
- verify_and_update() support: if Argon2 params are upgraded, the hash
  is rehashed and saved transparently during authentication, keeping
  stored hashes current.
- Pagination via limit/offset (not cursor-based) for simplicity;
  cursor-based pagination is listed as a future enhancement.
- No soft-delete logic here: is_active flag is in the User model but
  crud doesn't filter inactive users. Routes decide whether to query
  inactive users.
- No API layer logic: this module strictly handles database operations. 
  API-specific concerns, such as request validation, response formatting, and 
  HTTP status codes, are handled in the route handlers.
- The returned objects are SQLAlchemy ORM instances.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from models import User, Task
from schemas import TaskCreate, TaskUpdate, UserCreate, UserAdminUpdate
from security import get_password_hash, verify_password, DUMMY_HASH

_DEFAULT_LIMIT_USERS = 100
_DEFAULT_LIMIT_TASKS = 100

# USERS


def authenticate(*, db: Session, email: str, password: str) -> User | None:
    """
    Authenticate a user by email and password.

    Looks up a user by email, verifies the provided password against the stored
    Argon2 hash, and handles hash upgrades if Argon2 parameters have changed.
    Implements timing-attack mitigation by checking a dummy hash when the user
    doesn't exist.

    Args:
        db: Database session.
        email: User's email address.
        password: User-provided plaintext password.

    Returns:
        The authenticated User ORM object if email and password match.
        None if the user doesn't exist or the password is incorrect.
        (Both cases return None to avoid timing-based enumeration attacks.)

    Design decisions:
    - Even if the user doesn't exist, calls verify_password(DUMMY_HASH) to maintain
      constant-time behavior. Otherwise, the response time would differ between
      "user not found" and "wrong password", leaking information about whether the
      email exists in the database.
    - If Argon2 parameters are upgraded (e.g., higher memory cost), verify_and_update()
      returns an updated hash. This function saves the new hash back to the database
      (db.commit()), keeping stored credentials current without requiring a password change.
    - Used by the POST /auth/token endpoint to validate login credentials.
    """
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
    """
    Retrieve a user by their primary key (ID).

    Args:
        db: Database session.
        user_id: User's id column value.

    Returns:
        The User ORM object if found, None otherwise.
    """
    return db.get(User, user_id)


def get_user_by_username(*, db: Session, username: str) -> User | None:
    """
    Retrieve a user by their unique username.

    Uses SQLAlchemy's select() query with bound parameters (prevents
    SQL injection).

    Args:
        db: Database session.
        username: User's username column value.

    Returns:
        The User ORM object if found, None otherwise.
    """
    stmt = select(User).where(User.username == username)
    return db.scalars(stmt).first()


def get_user_by_email(*, db: Session, email: str) -> User | None:
    """
    Retrieve a user by their unique email address.

    Args:
        db: Database session.
        email: User's email column value.

    Returns:
        The User ORM object if found, None otherwise.
    """
    stmt = select(User).where(User.email == email)
    return db.scalars(stmt).first()


def get_all_users(
    *, db: Session, limit: int = _DEFAULT_LIMIT_USERS, offset: int = 0
) -> list[User]:
    """
    Retrieve all users with pagination.

    Returns users ordered by ID with limit/offset pagination.

    Args:
        db: Database session.
        limit: Maximum number of users to return (default 100, capped
               elsewhere).
        offset: Number of users to skip (default 0 for first page).

    Returns:
        List of User ORM objects (may be empty if offset exceeds total
        users).

    Design decisions:
    - Limit/offset is simple but has quirks: if a user is added/deleted
      between requests, offsets can skip records or repeat them.
      Cursor-based pagination (future enhancement) would solve this.
    """
    stmt = select(User).order_by(User.id).limit(limit).offset(offset)
    return list(db.scalars(stmt).all())


def create_user(*, db: Session, user_in: UserCreate) -> User:
    """
    Create a new user account.

    Args:
        db: Database session.
        user_in: UserCreate schema with username, email, plaintext
                 password.

    Returns:
        The created User ORM object (with id assigned by PostgreSQL).

    Raises:
        Implicit SQLAlchemy IntegrityError if username or email already
        exists (violated unique constraint). The route handler catches
        this and returns a 409 Conflict response to the client.

    Design decisions:
    - Password hashing is done by get_password_hash() before
      instantiating the User object; plaintext password is never stored.
    - Unique constraints on username and email are enforced at the
      database level. If two requests try to create a user with the
      same email, one will fail with an IntegrityError, preventing race
      conditions.
    - db.refresh() reloads the user from the database to get the
      auto-generated id.
    """
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
    """
    Update a user's attributes.

    Takes a User object and a UserAdminUpdate schema (with optional
    fields like is_active, is_admin), applies the changes, commits to
    the database, and returns the refreshed object. Used for admin endpoints.

    Args:
        db: Database session.
        user: The User object to update (attached to this session).
        user_update: UserAdminUpdate schema with fields to change
                     (others are ignored).

    Returns:
        The updated User ORM object.

    Design decisions:
    - Uses model_dump(exclude_unset=True) so only explicitly set fields
      are updated. If the client doesn't send is_admin, the user's
      is_admin is not changed.
    - Used by PATCH /admin/users/{user_id} endpoint (admin-only).
    - Does not handle password updates (intentionally). Users change
      their own passwords via a separate endpoint that re-authenticates;
      admins cannot reset user passwords (future enhancement).
    """
    for field, value in user_update.model_dump(exclude_unset=True).items():
        setattr(user, field, value)
    db.commit()
    db.refresh(user)
    return user


def delete_user(*, db: Session, user: User) -> None:
    """
    Delete a user account.

    Args:
        db: Database session.
        user: The User object to delete.

    Design decisions:
    - Deleting the User automatically deletes all related Tasks (cascade delete
      is configured on the User.tasks relationship and PostgreSQL foreign-key).
    """
    db.delete(user)
    db.commit()


# TASKS

def get_task_by_id(*, db: Session, task_id: int) -> Task | None:
    """
    Retrieve a task by its primary key (ID).

    Args:
        db: Database session.
        task_id: Task's id column value.

    Returns:
        The Task ORM object if found, None otherwise.
    """
    return db.get(Task, task_id)


def get_tasks_by_user(
    *, db: Session, user: User, limit: int = _DEFAULT_LIMIT_TASKS, offset: int = 0
) -> list[Task]:
    """
    Retrieve all tasks owned by a specific user with pagination.

    Args:
        db: Database session.
        user: The User object whose tasks to retrieve.
        limit: Maximum number of tasks to return (default 100).
        offset: Number of tasks to skip (default 0).

    Returns:
        List of Task ORM objects owned by the user (may be empty).

    Design decisions:
    - Filters by user.id to enforce object-level authorization: a user
      can only see/list their own tasks. Used by GET /tasks/ endpoint.
    - Ordered by ID for consistency; pagination via limit/offset.
    """
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
    """
    Retrieve all tasks (across all users) with pagination.

    Args:
        db: Database session.
        limit: Maximum number of tasks to return (default 100).
        offset: Number of tasks to skip (default 0).

    Returns:
        List of Task ORM objects (may be empty).

    Design decisions:
    - Used by GET /admin/tasks endpoint (admin-only). Admins can view
      all tasks.
    - Does not filter by user; return all tasks in the system.
    """
    stmt = select(Task).order_by(Task.id).limit(limit).offset(offset)
    return list(db.scalars(stmt).all())


def create_task(*, db: Session, user_id: int, task_in: TaskCreate) -> Task:
    """
    Create a new task owned by a specific user.

    Args:
        db: Database session.
        user_id: The id of the User who owns this task.
        task_in: TaskCreate schema with title, description, and other
                 fields.

    Returns:
        The created Task ORM object (with id assigned by PostgreSQL,
        created_at set).

    Design decisions:
    - user_id is passed separately (not from task_in) to prevent users
      from creating tasks assigned to other users (security:
      object-level authorization).
    - created_at is set automatically by the Task model's default, so
      it's not in the TaskCreate schema.
    - db.refresh() reloads the task to get the auto-generated id and
      confirm created_at was set by the database.
    """
    db_task = Task(
        user_id=user_id,
        **task_in.model_dump(),
    )
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task


def update_task(*, db: Session, task: Task, task_in: TaskUpdate) -> Task:
    """
    Update a task's attributes.

    Takes a Task object and a TaskUpdate schema (with optional fields
    like title, description, completed), applies the changes, commits
    to the database, and returns the refreshed object.

    Args:
        db: Database session.
        task: The Task object to update (attached to this session).
        task_in: TaskUpdate schema with fields to change (others are
                 ignored).

    Returns:
        The updated Task ORM object.

    Design decisions:
    - Uses model_dump(exclude_unset=True) so only explicitly set fields
      are updated. If the client only sends {"completed": true}, other
      fields are unchanged.
    - Does not expose created_at in TaskUpdate schema (immutable after
      creation).
    - user_id cannot be changed (not in TaskUpdate schema). Tasks are
      permanently owned by their creating user.
    """
    for field, value in task_in.model_dump(exclude_unset=True).items():
        setattr(task, field, value)
    db.commit()
    db.refresh(task)
    return task


def delete_task(*, db: Session, task: Task) -> None:
    """
    Delete a task.

    Args:
        db: Database session.
        task: The Task object to delete.

    Design decisions:
    - Hard delete: task and its data are removed permanently.
    """
    db.delete(task)
    db.commit()
