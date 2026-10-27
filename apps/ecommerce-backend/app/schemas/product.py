from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ProductOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    description: str
    category: str
    price: float
    stock: int
    is_active: bool
    created_at: datetime


class ProductCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: str = Field(min_length=2, max_length=255)
    description: str = Field(default="")
    category: str = Field(min_length=2, max_length=64)
    price: float = Field(gt=0)
    stock: int = Field(ge=0, default=10)


class ProductFilter(BaseModel):
    category: str | None = None
    search: str | None = None
    min_price: float | None = None
    max_price: float | None = None
    limit: int = 50
    offset: int = 0
