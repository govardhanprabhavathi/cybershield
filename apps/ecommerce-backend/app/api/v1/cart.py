from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.schemas.cart import CartItemIn, CartItemOut, CartItemUpdate, CartSummaryOut
from app.services.cart_service import CartService

router = APIRouter()


@router.get(
    "",
    response_model=CartSummaryOut,
    status_code=status.HTTP_200_OK,
    summary="Get current user shopping cart",
)
async def get_cart(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await CartService.get_cart(db, current_user.id)


@router.post(
    "/items",
    response_model=CartItemOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add an item to the user's shopping cart",
)
async def add_item_to_cart(
    item_in: CartItemIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await CartService.add_item(db, current_user.id, item_in)


@router.patch(
    "/items/{item_id}",
    response_model=CartItemOut,
    status_code=status.HTTP_200_OK,
    summary="Update quantity of a cart item",
)
async def update_cart_item(
    item_id: str,
    update_in: CartItemUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await CartService.update_item(db, current_user.id, item_id, update_in)


@router.delete(
    "/items/{item_id}",
    status_code=status.HTTP_200_OK,
    summary="Remove an item from the cart",
)
async def remove_cart_item(
    item_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await CartService.remove_item(db, current_user.id, item_id)
    return {"status": "success", "message": "Item removed from cart"}


@router.delete(
    "",
    status_code=status.HTTP_200_OK,
    summary="Clear all items from the shopping cart",
)
async def clear_cart(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await CartService.clear_cart(db, current_user.id)
    return {"status": "success", "message": "Cart cleared"}
