from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.schemas.auth import TokenResponse, UserLoginRequest, UserRegisterRequest
from app.schemas.user import UserOut
from app.services.auth_service import AuthService

router = APIRouter()


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new customer account",
)
async def register(request: UserRegisterRequest, db: AsyncSession = Depends(get_db)):
    user = await AuthService.register(db, request)
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and issue session token",
)
async def login(
    request: UserLoginRequest,
    req: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = req.client.host if req.client else "127.0.0.1"
    token_response = await AuthService.login(db, request, ip=client_ip)
    return token_response


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Revoke token and terminate session in fast-state store",
)
async def logout(current_user: User = Depends(get_current_user)):
    session_id = getattr(current_user, "_current_session_id", "")
    jti = getattr(current_user, "_current_jti", "")
    await AuthService.logout(session_id=session_id, jti=jti)
    return {"status": "success", "message": "Successfully logged out and session revoked"}


@router.get(
    "/me",
    response_model=UserOut,
    status_code=status.HTTP_200_OK,
    summary="Retrieve authenticated user profile",
)
async def get_profile(current_user: User = Depends(get_current_user)):
    return current_user
