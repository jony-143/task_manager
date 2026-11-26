"""
SQLAlchemy ORM models for User and Task entities.

This module defines the relational database schema using SQLAlchemy
2.0's declarative mapping with type annotations. Models map to
PostgreSQL tables and define relationships with cascading deletes.

Design decisions:
- Uses SQLAlchemy ORM (not raw SQL) to prevent SQL injection and
  provide type safety through Python objects.
- Cascade delete: deleting a User automatically deletes their Tasks.
  This is enforced both via SQLAlchemy ORM cascade and PostgreSQL
  foreign-key constraints. Doing so ensures robustness of data integrity.
- Timezone-aware task timestamps: created_at uses datetime with UTC
  timezone to ensure consistency across deployments and timezones.
- Email field length 254 (RFC 5321): allows for maximum valid email
  length.
- Username/email uniqueness: enforced at database level to prevent
  duplicate accounts.
"""

from datetime import datetime, timezone
from typing import List
from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class User(Base):
    """
    User account ORM entity representing an authenticated user.

    This model stores user authentication credentials, role information,
    and maintains a one-to-many relationship with Tasks. Each user can
    own multiple tasks, and deleting a user cascades to delete all their
    tasks.

    Attributes:
        id: Primary key; auto-incremented by PostgreSQL.
        username: Unique username for login and identification (max 50
                  chars).
        email: Unique email address for account recovery (max 254 chars
               per RFC 5321).
        password_hash: Argon2 hash of the user's password, never the
                       plaintext.
        is_active: Soft-delete flag; inactive users cannot access the
                   API.
        is_admin: Role flag; True grants access to admin endpoints.
        tasks: Reverse relationship to Task. When a User is deleted, all
               related Tasks are deleted via cascade.

    Design decisions:
    - Unique constraints on username and email enable efficient database
      queries and prevent duplicate accounts.
    - is_active allows deactivating users without hard-deleting their
      data.
    - Cascade delete simplifies data integrity: no orphaned tasks
      remain.
    - Password stored as hash only; plaintext password never persisted.
    """

    __tablename__ = "user_account"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    email: Mapped[str] = mapped_column(
        String(254), unique=True)  # RFC standard
    password_hash: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(default=True)
    is_admin: Mapped[bool] = mapped_column(
        default=False, server_default="false")

    tasks: Mapped[List["Task"]] = relationship(
        back_populates="user",
        cascade="all, delete",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, username={self.username!r}, email={self.email!r})"


class Task(Base):
    """
    Task entity representing a user-owned task.

    Models a task item that belongs to exactly one User. Each task has
    a title, description, completion status, and creation timestamp.
    Deleting the owning User automatically deletes this task via cascade.

    Attributes:
        id: Primary key; auto-incremented by PostgreSQL.
        user_id: Foreign key to User.id. OnDelete CASCADE ensures
                 referential integrity: orphaned tasks cannot exist. It
                 imposes a DB schema constraint.
        title: Task name or headline (max 40 chars).
        description: Detailed task description (unlimited length via
                     Text).
        completed: Boolean flag; False by default. Users toggle this via
                   PATCH.
        created_at: Timestamp with UTC timezone. Set automatically at
                    creation; immutable after insertion (task routes don't
                    update it).
        user: Reverse relationship to User; allows accessing the owning
              user.

    Design decisions:
    - Timezone-aware created_at (datetime(timezone=True)) ensures
      consistent timestamps across different server timezones and during
      DST transitions.
    - Foreign-key cascade + ORM cascade = doubly-enforced referential
      integrity.
    - Immutable creation timestamp: not exposed in TaskUpdate schema to
      prevent accidental or malicious time tampering.
    - completed defaults to False at database level; users explicitly
      mark tasks done.
    """

    __tablename__ = "task"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(Text)
    completed: Mapped[bool] = mapped_column(default=False)  # Python default
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    user: Mapped[User] = relationship(back_populates="tasks")

    def __repr__(self) -> str:
        return f"Task(id={self.id!r}, title={self.title!r}, description={self.description!r}, completed={self.completed!r}, created_at={self.created_at!r})"
