import uuid
from datetime import UTC, datetime, timedelta

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.redis import get_redis
from app.models.user import User
from app.schemas.auth import TokenPayload

settings = get_settings()

security_bearer = HTTPBearer(auto_error=True)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against the stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8")[:72],
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def get_password_hash(password: str) -> str:
    """Generate a secure bcrypt hash of the password."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def create_access_token(
    user_id: str,
    email: str,
    role: str,
    session_id: str | None = None,
    jti: str | None = None,
    expires_delta: timedelta | None = None,
) -> tuple[str, str, str, int]:
    """Issue a signed JWT access token containing session_id and jti claims."""
    if session_id is None:
        session_id = str(uuid.uuid4())
    if jti is None:
        jti = str(uuid.uuid4())

    expire_minutes = (
        int(expires_delta.total_seconds() / 60)
        if expires_delta
        else settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    expires_at = datetime.now(UTC) + timedelta(minutes=expire_minutes)

    to_encode = {
        "sub": user_id,
        "email": email,
        "role": role,
        "session_id": session_id,
        "jti": jti,
        "exp": int(expires_at.timestamp()),
    }

    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt, session_id, jti, expire_minutes * 60


def decode_access_token(token: str) -> TokenPayload:
    """Decode and validate claims of an incoming JWT token."""
    try:
        payload_dict = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return TokenPayload(**payload_dict)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Authenticate incoming request and verify both token revocation and session risk state in Redis."""
    token = credentials.credentials
    payload = decode_access_token(token)

    # Fast Path 1: Check Redis for session containment by runtime security policy
    redis_client = await get_redis()
    session_status = await redis_client.hget(f"session:risk:{payload.session_id}", "status")
    session_state = await redis_client.hget(f"session:risk:{payload.session_id}", "state")
    if session_status in ("CONTAIN", "CONTAINED") or session_state in ("CONTAIN", "CONTAINED"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session has been contained by CyberShield runtime security policy",
        )

    # Fast Path 2: Check Redis for token revocation (e.g., logout or manual revocation)
    is_revoked = await redis_client.get(f"revoked:jti:{payload.jti}")
    if is_revoked or session_status == "REVOKED":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Retrieve User from DB
    result = await db.execute(select(User).where(User.id == payload.sub))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or not found",
        )

    # Attach session metadata dynamically to user instance for route access
    user._current_session_id = payload.session_id
    user._current_jti = payload.jti

    return user


async def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    """Ensure the authenticated user holds administrative privileges."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required",
        )
    return current_user
