# from fastapi import FastAPI
from datetime import datetime
from typing import Annotated
from typing_extensions import Self
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    EmailStr,
    StringConstraints,
    model_validator,
)

# ---------- TOKENS ----------


class Token(BaseModel):
    access_token: str
    token_type: str


# ---------- USERS ----------
_User_Password = Annotated[str, StringConstraints(
    min_length=8, max_length=128)]
_User_Username = Annotated[str, StringConstraints(
    to_lower=True, max_length=50)]
_User_Email = Annotated[
    EmailStr,
    BeforeValidator(lambda v: v.lower() if isinstance(v, str) else v),
]


class PasswordConfirmation(BaseModel):
    password: _User_Password


class UserBase(BaseModel):
    username: _User_Username
    email: _User_Email


class UserCreate(UserBase):
    password: _User_Password


class UserOut(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int


class UserOutAdmin(UserOut):
    model_config = ConfigDict(from_attributes=True)

    is_active: bool
    is_admin: bool


class UserAdminUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool | None = None
    is_admin: bool | None = None

    @model_validator(mode="after")
    def check_empty_input(self) -> Self:
        if self.is_active is None and self.is_admin is None:
            raise ValueError("At least one field must be provided")
        return self


# ---------- TASKS ----------
_Title = Annotated[str, StringConstraints(max_length=40)]
_Description = Annotated[str, StringConstraints(max_length=2000)]


class TaskBase(BaseModel):
    title: _Title
    description: _Description


class TaskCreate(TaskBase):
    pass


class TaskUpdate(TaskBase):
    model_config = ConfigDict(extra="forbid")

    title: _Title | None = None
    description: _Description | None = None
    completed: bool | None = None


class TaskOut(TaskBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    completed: bool
    created_at: datetime
