from datetime import datetime, timedelta
from typing import Annotated

from fastapi.responses import JSONResponse
from app.core.auth_util import (
    check_password,
    decode_token,
    encrypt_password,
    generate_token,
)

from app.database import SessionLocal
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from app.models import user as user_model
from app.models import token as token_model
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlmodel import SQLModel
from starlette import status

from app.core.config import settings
from app.core.logger import logger

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM

bcrypt = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")


@router.post(
    "/signup", status_code=status.HTTP_201_CREATED, response_model=user_model.UserRead
)
async def create_user(
    user_create: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> user_model.User:
    try:
        with SessionLocal() as db:
            existing_user = (
                db.query(user_model.User)
                .filter(user_model.User.username == user_create.username)
                .first()
            )
            if not existing_user:
                user_create.password = encrypt_password(user_create.password)
                db_user = user_model.User.model_validate(user_create)
                db.add(db_user)
                db.commit()
                db.refresh(db_user)
                return user_model.UserRead(username=db_user.username, suceess=True)
    except Exception as e:
        logger.error(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        ) from e
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="User already exists",
    )


@router.post("/token", response_model=token_model.Token)
async def login_for_access_token(
    token: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> token_model.Token:
    with SessionLocal() as db:
        db_user = (
            db.query(user_model.User)
            .filter(user_model.User.username == token.username)
            .first()
        )
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_401_NOT_FOUND,
                detail="Incorrect username",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not check_password(token.password, db_user.password):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incorrect password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token = generate_token(username=token.username)
        return token_model.Token(access_token=access_token, token_type="bearer")


@router.get("/me")
async def read_users_me(
    token: Annotated[str, Depends(oauth2_bearer)],
) -> user_model.UserRead:
    try:
        payload = decode_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = token_model.TokenData(username=username)
    except JWTError as e:
        logger.error(e)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    with SessionLocal() as db:
        db_user = (
            db.query(user_model.User)
            .filter(user_model.User.username == token_data.username)
            .first()
        )
        if db_user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return user_model.UserRead(username=db_user.username, suceess=True)
