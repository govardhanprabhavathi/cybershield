from app.core.config import get_settings
from app.models.cart import CartItem
from app.models.product import Product
from app.schemas.cart import CartItemIn, CartItemOut, CartItemUpdate, CartSummaryOut
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

settings = get_settings()


class CartService:
    """Shopping cart management service with sensitive business flow controls."""

    @staticmethod
    async def get_cart(db: AsyncSession, user_id: str) -> CartSummaryOut:
        result = await db.execute(
            select(CartItem)
            .where(CartItem.user_id == user_id)
            .options(selectinload(CartItem.product))
        )
        cart_records = result.scalars().all()

        items_out = []
        subtotal = 0.0
        total_items = 0

        for item in cart_records:
            price = item.product.price if item.product else 0.0
            line_total = round(price * item.quantity, 2)
            subtotal += line_total
            total_items += item.quantity
            items_out.append(
                CartItemOut(
                    id=item.id,
                    product_id=item.product_id,
                    product_name=item.product.name if item.product else "Unknown Product",
                    unit_price=price,
                    quantity=item.quantity,
                    total_price=line_total,
                )
            )

        return CartSummaryOut(
            items=items_out,
            total_items=total_items,
            subtotal=round(subtotal, 2),
        )

    @staticmethod
    async def add_item(db: AsyncSession, user_id: str, item_in: CartItemIn) -> CartItemOut:
        # Business Flow Abuse Toggle Check:
        # If disabled: strictly enforce quantity >= 1
        # If enabled: allow negative quantity to simulate business logic pricing flaw
        if not settings.ENABLE_VULNERABILITY_BUSINESS_FLOW and item_in.quantity <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Item quantity must be a positive integer greater than zero",
            )

        # Check product existence
        prod_result = await db.execute(select(Product).where(Product.id == item_in.product_id))
        product = prod_result.scalar_one_or_none()
        if not product or not product.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Product not found or currently unavailable",
            )

        # Check if item already exists in user cart
        cart_result = await db.execute(
            select(CartItem).where(
                CartItem.user_id == user_id,
                CartItem.product_id == item_in.product_id,
            )
        )
        existing_item = cart_result.scalar_one_or_none()

        if existing_item:
            existing_item.quantity += item_in.quantity
            target_item = existing_item
        else:
            new_item = CartItem(
                user_id=user_id,
                product_id=item_in.product_id,
                quantity=item_in.quantity,
            )
            db.add(new_item)
            target_item = new_item

        await db.commit()
        await db.refresh(target_item)

        line_total = round(product.price * target_item.quantity, 2)
        return CartItemOut(
            id=target_item.id,
            product_id=product.id,
            product_name=product.name,
            unit_price=product.price,
            quantity=target_item.quantity,
            total_price=line_total,
        )

    @staticmethod
    async def update_item(
        db: AsyncSession, user_id: str, item_id: str, update_in: CartItemUpdate
    ) -> CartItemOut:
        if not settings.ENABLE_VULNERABILITY_BUSINESS_FLOW and update_in.quantity <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Quantity must be greater than zero",
            )

        result = await db.execute(
            select(CartItem)
            .where(CartItem.id == item_id, CartItem.user_id == user_id)
            .options(selectinload(CartItem.product))
        )
        cart_item = result.scalar_one_or_none()
        if not cart_item:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cart item not found")

        cart_item.quantity = update_in.quantity
        await db.commit()
        await db.refresh(cart_item)

        price = cart_item.product.price if cart_item.product else 0.0
        return CartItemOut(
            id=cart_item.id,
            product_id=cart_item.product_id,
            product_name=cart_item.product.name if cart_item.product else "Unknown",
            unit_price=price,
            quantity=cart_item.quantity,
            total_price=round(price * cart_item.quantity, 2),
        )

    @staticmethod
    async def remove_item(db: AsyncSession, user_id: str, item_id: str):
        result = await db.execute(
            select(CartItem).where(CartItem.id == item_id, CartItem.user_id == user_id)
        )
        cart_item = result.scalar_one_or_none()
        if not cart_item:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cart item not found")

        await db.delete(cart_item)
        await db.commit()

    @staticmethod
    async def clear_cart(db: AsyncSession, user_id: str):
        result = await db.execute(select(CartItem).where(CartItem.user_id == user_id))
        for item in result.scalars().all():
            await db.delete(item)
        await db.commit()
