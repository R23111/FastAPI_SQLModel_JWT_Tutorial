from datetime import datetime, timedelta
import bcrypt

from jose import jwt

from app.core.config import settings
from datetime import timezone


def encrypt_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def generate_token(
    username: str, expires_delta=settings.ACCESS_TOKEN_EXPIRE_MINUTES
):
    data = {"sub": username}
    exprires = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
    data |= {"exp": exprires}

    return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token):
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
