import re
import uuid

from app.core.config import get_settings
from app.models.product import Product
from app.schemas.product import ProductCreate, ProductFilter
from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

settings = get_settings()


class ProductService:
    """Product catalog service with configurable vulnerability toggles."""

    @staticmethod
    async def list_products(db: AsyncSession, filters: ProductFilter) -> list[Product]:
        # Unrestricted Resource Consumption Toggle Check
        limit = filters.limit
        if not settings.ENABLE_VULNERABILITY_RESOURCE_CONSUMPTION:
            limit = min(max(1, filters.limit), 100)

        # SQL Injection Toggle Check on Search Parameter
        if filters.search and settings.ENABLE_VULNERABILITY_SQLI:
            # Controlled Flaw: Direct string interpolation into raw SQL query
            # Allows demonstration of UNION-based, boolean-based, or error-based SQLi
            raw_sql = f"SELECT id, name, slug, description, category, price, stock, is_active, created_at, updated_at FROM products WHERE is_active = 1 AND (name LIKE '%{filters.search}%' OR description LIKE '%{filters.search}%') LIMIT {limit} OFFSET {filters.offset}"
            try:
                result = await db.execute(text(raw_sql))
                rows = result.mappings().all()
                products = []
                for row in rows:
                    products.append(Product(**row))
                return products
            except Exception as exc:
                # Controlled error leak when SQL syntax is broken by injection payload
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Database execution error: {exc}",
                ) from exc

        # Safe Parameterized Query Path
        query = select(Product).where(Product.is_active.is_(True))

        if filters.category:
            query = query.where(Product.category == filters.category)
        if filters.search:
            search_pattern = f"%{filters.search}%"
            query = query.where(
                (Product.name.ilike(search_pattern)) | (Product.description.ilike(search_pattern))
            )
        if filters.min_price is not None:
            query = query.where(Product.price >= filters.min_price)
        if filters.max_price is not None:
            query = query.where(Product.price <= filters.max_price)

        query = query.offset(filters.offset).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(db: AsyncSession, product_id: str) -> Product:
        result = await db.execute(select(Product).where(Product.id == product_id))
        product = result.scalar_one_or_none()
        if not product:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
        return product

    @staticmethod
    async def get_categories(db: AsyncSession) -> list[str]:
        result = await db.execute(
            select(Product.category).distinct().where(Product.is_active.is_(True))
        )
        return [row[0] for row in result.all() if row[0]]

    @staticmethod
    async def create(db: AsyncSession, data: ProductCreate) -> Product:
        base_slug = re.sub(r"[^a-zA-Z0-9]+", "-", data.name.lower()).strip("-")
        slug = base_slug
        existing = await db.execute(select(Product).where(Product.slug == slug))
        if existing.scalar_one_or_none():
            slug = f"{base_slug}-{uuid.uuid4().hex[:6]}"

        product = Product(
            name=data.name,
            slug=slug,
            description=data.description,
            category=data.category,
            price=data.price,
            stock=data.stock,
            is_active=True,
        )
        db.add(product)
        await db.commit()
        await db.refresh(product)
        return product
