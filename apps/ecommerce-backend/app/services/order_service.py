import random
import time

from app.core.config import get_settings
from app.models.cart import CartItem
from app.models.order import Order, OrderItem, Payment
from app.models.user import User
from app.schemas.order import OrderCreate, OrderItemOut, OrderOut, PaymentOut, PaymentRequest
from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

settings = get_settings()


class OrderService:
    """Order lifecycle and checkout service with controlled BOLA vulnerability."""

    @staticmethod
    def _format_order_out(order: Order) -> OrderOut:
        items_out = []
        for item in order.items:
            items_out.append(
                OrderItemOut(
                    id=item.id,
                    product_id=item.product_id,
                    product_name=item.product.name if item.product else "Item",
                    quantity=item.quantity,
                    unit_price=item.unit_price,
                    total_price=item.total_price,
                )
            )
        payment_status = order.payment.status if order.payment else "unpaid"
        return OrderOut(
            id=order.id,
            order_number=order.order_number,
            user_id=order.user_id,
            total_amount=order.total_amount,
            status=order.status,
            shipping_address=order.shipping_address,
            created_at=order.created_at,
            items=items_out,
            payment_status=payment_status,
        )

    @staticmethod
    async def create_order(db: AsyncSession, user_id: str, create_in: OrderCreate) -> OrderOut:
        # Fetch cart items
        result = await db.execute(
            select(CartItem)
            .where(CartItem.user_id == user_id)
            .options(selectinload(CartItem.product))
        )
        cart_items = result.scalars().all()
        if not cart_items:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot create order from an empty cart",
            )

        # Generate collision-safe order number under high concurrency
        max_num_res = await db.execute(select(func.max(Order.order_number)))
        highest_num = max_num_res.scalar_one_or_none() or 1000
        time_offset = int(time.time() * 1000) % 100000
        next_order_num = highest_num + time_offset + random.randint(1, 99)

        total_amount = 0.0
        order_items = []

        for c_item in cart_items:
            if not c_item.product:
                continue
            line_total = round(c_item.product.price * c_item.quantity, 2)
            total_amount += line_total
            order_items.append(
                OrderItem(
                    product_id=c_item.product_id,
                    quantity=c_item.quantity,
                    unit_price=c_item.product.price,
                    total_price=line_total,
                )
            )
            # Deduct stock
            c_item.product.stock = max(0, c_item.product.stock - c_item.quantity)

        new_order = Order(
            order_number=next_order_num,
            user_id=user_id,
            total_amount=round(total_amount, 2),
            status="pending",
            shipping_address=create_in.shipping_address,
            items=order_items,
        )
        db.add(new_order)

        # Clear user cart
        for c_item in cart_items:
            await db.delete(c_item)

        await db.commit()
        await db.refresh(new_order)

        # Reload with relationships
        reloaded = await db.execute(
            select(Order)
            .where(Order.id == new_order.id)
            .options(
                selectinload(Order.items).selectinload(OrderItem.product),
                selectinload(Order.payment),
            )
        )
        return OrderService._format_order_out(reloaded.scalar_one())

    @staticmethod
    async def list_user_orders(db: AsyncSession, user_id: str) -> list[OrderOut]:
        result = await db.execute(
            select(Order)
            .where(Order.user_id == user_id)
            .options(
                selectinload(Order.items).selectinload(OrderItem.product),
                selectinload(Order.payment),
            )
            .order_by(Order.created_at.desc())
        )
        orders = result.scalars().all()
        return [OrderService._format_order_out(o) for o in orders]

    @staticmethod
    async def get_order_by_id(db: AsyncSession, current_user: User, order_id: str) -> OrderOut:
        result = await db.execute(
            select(Order)
            .where(Order.id == order_id)
            .options(
                selectinload(Order.items).selectinload(OrderItem.product),
                selectinload(Order.payment),
            )
        )
        order = result.scalar_one_or_none()
        if not order:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

        # BOLA / IDOR Toggle Check:
        # When enabled: Bypasses user ownership verification (OWASP API1 flaw)
        # When disabled: Enforces strict tenant isolation
        if (
            not settings.ENABLE_VULNERABILITY_BOLA
            and order.user_id != current_user.id
            and current_user.role != "admin"
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You do not have permission to access this order",
            )

        return OrderService._format_order_out(order)

    @staticmethod
    async def pay_order(
        db: AsyncSession, current_user: User, payment_req: PaymentRequest
    ) -> PaymentOut:
        result = await db.execute(
            select(Order)
            .where(Order.id == payment_req.order_id)
            .options(selectinload(Order.payment))
        )
        order = result.scalar_one_or_none()
        if not order:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

        if order.user_id != current_user.id and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Cannot settle payment for another user's order",
            )

        if order.status == "paid":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This order has already been paid",
            )

        payment = Payment(
            order_id=order.id,
            payment_method=payment_req.payment_method,
            amount=order.total_amount,
            status="success",
        )
        order.status = "paid"
        db.add(payment)
        await db.commit()
        await db.refresh(payment)

        return PaymentOut(
            id=payment.id,
            order_id=payment.order_id,
            payment_method=payment.payment_method,
            amount=payment.amount,
            status=payment.status,
            transaction_reference=payment.transaction_reference,
            created_at=payment.created_at,
        )
