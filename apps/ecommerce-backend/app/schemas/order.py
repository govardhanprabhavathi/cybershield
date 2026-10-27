from datetime import datetime

from pydantic import BaseModel, Field


class OrderCreate(BaseModel):
    shipping_address: str = Field(min_length=5, max_length=1024)


class OrderItemOut(BaseModel):
    id: str
    product_id: str
    product_name: str
    quantity: int
    unit_price: float
    total_price: float


class OrderOut(BaseModel):
    id: str
    order_number: int
    user_id: str
    total_amount: float
    status: str
    shipping_address: str
    created_at: datetime
    items: list[OrderItemOut]
    payment_status: str = "unpaid"


class PaymentRequest(BaseModel):
    order_id: str
    payment_method: str = Field(default="credit_card")


class PaymentOut(BaseModel):
    id: str
    order_id: str
    payment_method: str
    amount: float
    status: str
    transaction_reference: str
    created_at: datetime
