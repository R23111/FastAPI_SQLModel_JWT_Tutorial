from typing import Optional
from sqlalchemy import Column, Integer, String
from sqlmodel import Field, SQLModel


class UserBase(SQLModel):
    username: str


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    suceess: bool


class User(UserBase, table=True):
    id: Optional[int] = Field(
        default=None,
        sa_column=Column(
            Integer, primary_key=True, index=True, unique=True, autoincrement=True
        ),
    )
    username: str = Field(sa_column=Column(Integer, unique=True, index=True))
    password: str = Field(sa_column=Column(String))
