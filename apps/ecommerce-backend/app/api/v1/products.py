from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.schemas.product import ProductFilter, ProductOut
from app.services.product_service import ProductService

router = APIRouter()


@router.get(
    "",
    response_model=list[ProductOut],
    status_code=status.HTTP_200_OK,
    summary="List product catalog with optional search, categories, and price bounds",
)
async def list_products(
    category: str | None = Query(default=None),
    search: str | None = Query(default=None),
    min_price: float | None = Query(default=None, ge=0),
    max_price: float | None = Query(default=None, ge=0),
    limit: int = Query(default=50),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    filters = ProductFilter(
        category=category,
        search=search,
        min_price=min_price,
        max_price=max_price,
        limit=limit,
        offset=offset,
    )
    products = await ProductService.list_products(db, filters)
    return products


@router.get(
    "/categories",
    response_model=list[str],
    status_code=status.HTTP_200_OK,
    summary="List all distinct product categories",
)
async def get_categories(db: AsyncSession = Depends(get_db)):
    return await ProductService.get_categories(db)


@router.get(
    "/{product_id}",
    response_model=ProductOut,
    status_code=status.HTTP_200_OK,
    summary="Get single product by unique ID",
)
async def get_product(product_id: str, db: AsyncSession = Depends(get_db)):
    return await ProductService.get_by_id(db, product_id)
