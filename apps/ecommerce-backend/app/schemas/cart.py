from pydantic import BaseModel, Field


class CartItemIn(BaseModel):
    product_id: str
    quantity: int = Field(default=1)


class CartItemUpdate(BaseModel):
    quantity: int


class CartItemOut(BaseModel):
    id: str
    product_id: str
    product_name: str
    unit_price: float
    quantity: int
    total_price: float


class CartSummaryOut(BaseModel):
    items: list[CartItemOut]
    total_items: int
    subtotal: float
