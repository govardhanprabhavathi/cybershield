from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import get_current_admin
from app.models.order import Order, OrderItem
from app.models.user import User
from app.schemas.order import OrderOut
from app.schemas.product import ProductCreate, ProductOut
from app.schemas.user import UserOut
from app.services.order_service import OrderService
from app.services.product_service import ProductService

router = APIRouter()


@router.get(
    "/orders",
    response_model=list[OrderOut],
    status_code=status.HTTP_200_OK,
    summary="View all platform orders (Admin only)",
)
async def admin_list_orders(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Order)
        .options(
            selectinload(Order.items).selectinload(OrderItem.product),
            selectinload(Order.payment),
        )
        .order_by(Order.created_at.desc())
    )
    orders = result.scalars().all()
    return [OrderService._format_order_out(o) for o in orders]


@router.get(
    "/users",
    response_model=list[UserOut],
    status_code=status.HTTP_200_OK,
    summary="List all registered platform users (Admin only)",
)
async def admin_list_users(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())


@router.post(
    "/products",
    response_model=ProductOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new catalog product (Admin only)",
)
async def admin_create_product(
    data: ProductCreate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    return await ProductService.create(db, data)
