"""API Version 1 Package aggregating all sub-routers."""

from fastapi import APIRouter

from app.api.v1.admin import router as admin_router
from app.api.v1.auth import router as auth_router
from app.api.v1.cart import router as cart_router
from app.api.v1.health import router as health_router
from app.api.v1.orders import router as orders_router
from app.api.v1.products import router as products_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router, prefix="/health", tags=["Health & Status"])
api_v1_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_v1_router.include_router(products_router, prefix="/products", tags=["Products & Catalog"])
api_v1_router.include_router(cart_router, prefix="/cart", tags=["Shopping Cart"])
api_v1_router.include_router(orders_router, prefix="/orders", tags=["Orders & Checkout"])
api_v1_router.include_router(admin_router, prefix="/admin", tags=["Administration"])
