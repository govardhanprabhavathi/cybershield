from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.schemas.order import OrderCreate, OrderOut, PaymentOut, PaymentRequest
from app.services.order_service import OrderService

router = APIRouter()


@router.post(
    "",
    response_model=OrderOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new order from items currently in cart",
)
async def create_order(
    create_in: OrderCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await OrderService.create_order(db, current_user.id, create_in)


@router.get(
    "",
    response_model=list[OrderOut],
    status_code=status.HTTP_200_OK,
    summary="List order history for authenticated user",
)
async def list_orders(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await OrderService.list_user_orders(db, current_user.id)


@router.get(
    "/{order_id}",
    response_model=OrderOut,
    status_code=status.HTTP_200_OK,
    summary="Get single order details (Target for BOLA/IDOR evaluation)",
)
async def get_order(
    order_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await OrderService.get_order_by_id(db, current_user, order_id)


@router.post(
    "/checkout/pay",
    response_model=PaymentOut,
    status_code=status.HTTP_200_OK,
    summary="Simulate payment settlement for an existing order",
)
async def pay_order(
    payment_req: PaymentRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await OrderService.pay_order(db, current_user, payment_req)
