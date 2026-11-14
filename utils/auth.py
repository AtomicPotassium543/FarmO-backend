
import jwt
import uuid

from datetime import datetime, timedelta, timezone
from pwdlib import PasswordHash

import os

password_hash = PasswordHash.recommended()

def create_token(
    user_id: str,
    token_type: str,
    expires_delta: timedelta
):
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())

    payload = {
        "sub": user_id,
        "type": token_type,
        "jti": jti,
        "iat": now,
        "exp": now + expires_delta
    }

    token = jwt.encode(
        payload,
        os.getenv("JWT_SECRET"),
        algorithm=os.getenv("JWT_ALGORITHM")
    )

    return token, jti


def create_token_pair(user_id: str):
    access_token, _ = create_token(
        user_id,
        "access",
        timedelta(minutes=os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
    )

    refresh_token, refresh_jti = create_token(
        user_id,
        "refresh",
        timedelta(days=os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"))
    )

    return access_token, refresh_token, refresh_jti


def decode_token(token: str):
    return jwt.decode(
        token,
        os.getenv("JWT_SECRET"),
        algorithms=[os.getenv("JWT_ALGORITHM")]
    )
