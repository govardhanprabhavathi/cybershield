from datetime import UTC, datetime

from app.core.redis import get_redis
from app.core.security import create_access_token, get_password_hash, verify_password
from app.models.user import User
from app.schemas.auth import TokenResponse, UserLoginRequest, UserRegisterRequest
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class AuthService:
    """Authentication and session lifecycle service."""

    @staticmethod
    async def register(db: AsyncSession, request: UserRegisterRequest) -> User:
        result = await db.execute(select(User).where(User.email == request.email.lower()))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A user with this email address already exists",
            )

        user = User(
            email=request.email.lower(),
            hashed_password=get_password_hash(request.password),
            full_name=request.full_name,
            role="customer",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def login(db: AsyncSession, request: UserLoginRequest, ip: str = "127.0.0.1") -> TokenResponse:
        result = await db.execute(select(User).where(User.email == request.email.lower()))
        user = result.scalar_one_or_none()

        if not user or not verify_password(request.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated",
            )

        token, session_id, jti, expires_in = create_access_token(
            user_id=user.id,
            email=user.email,
            role=user.role,
        )

        # Record active session in Redis
        redis_client = await get_redis()
        session_key = f"session:{session_id}"
        await redis_client.hset(
            session_key,
            mapping={
                "session_id": session_id,
                "jti": jti,
                "user_id": user.id,
                "email": user.email,
                "role": user.role,
                "ip": ip,
                "created_at": datetime.now(UTC).isoformat(),
                "status": "NORMAL",
            },
        )
        await redis_client.expire(session_key, 86400)

        # Initialize session risk profile
        risk_key = f"session:risk:{session_id}"
        await redis_client.hset(
            risk_key,
            mapping={
                "risk_score": "0",
                "confidence_score": "0.0",
                "status": "NORMAL",
                "last_updated": datetime.now(UTC).isoformat(),
            },
        )
        await redis_client.expire(risk_key, 7200)

        return TokenResponse(
            access_token=token,
            session_id=session_id,
            expires_in=expires_in,
        )

    @staticmethod
    async def logout(session_id: str, jti: str, expires_in: int = 3600):
        """Immediately revoke active JWT token and terminate session in fast-state store."""
        redis_client = await get_redis()
        # Blacklist JTI
        await redis_client.set(f"revoked:jti:{jti}", "1", ex=expires_in)
        # Update session risk state to REVOKED
        await redis_client.hset(f"session:risk:{session_id}", "status", "REVOKED")
        await redis_client.hset(f"session:{session_id}", "status", "REVOKED")
