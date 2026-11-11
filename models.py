from datetime import datetime, timezone
from typing import List
from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class User(Base):
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
