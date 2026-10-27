import pytest
from app.core.config import get_settings
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_all_products(async_client: AsyncClient):
    response = await async_client.get("/api/v1/products")
    assert response.status_code == 200
    products = response.json()
    assert len(products) >= 10


@pytest.mark.asyncio
async def test_filter_products_by_category(async_client: AsyncClient):
    response = await async_client.get("/api/v1/products?category=Hardware+Security")
    assert response.status_code == 200
    products = response.json()
    assert len(products) > 0
    for p in products:
        assert p["category"] == "Hardware Security"


@pytest.mark.asyncio
async def test_get_categories(async_client: AsyncClient):
    response = await async_client.get("/api/v1/products/categories")
    assert response.status_code == 200
    categories = response.json()
    assert "Hardware Security" in categories
    assert "Laptops" in categories


@pytest.mark.asyncio
async def test_get_single_product(async_client: AsyncClient):
    list_res = await async_client.get("/api/v1/products")
    product_id = list_res.json()[0]["id"]

    single_res = await async_client.get(f"/api/v1/products/{product_id}")
    assert single_res.status_code == 200
    assert single_res.json()["id"] == product_id


@pytest.mark.asyncio
async def test_product_search_and_sqli_toggle(async_client: AsyncClient):
    settings = get_settings()
    settings.ENABLE_VULNERABILITY_SQLI = True

    # Normal search
    safe_search = await async_client.get("/api/v1/products?search=YubiKey")
    assert safe_search.status_code == 200
    assert len(safe_search.json()) >= 1

    # Injection simulation: SQL syntax break triggers 500 error due to unescaped execution
    malformed_search = await async_client.get("/api/v1/products?search=' OR UNCLOSED_SYNTAX")
    assert malformed_search.status_code == 500
    assert "Database execution error" in malformed_search.json()["detail"]


@pytest.mark.asyncio
async def test_admin_create_product_rbac(async_client: AsyncClient):
    # Customer token (Alice)
    alice_login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "alice@cybershield.io", "password": "AlicePass123!"},
    )
    alice_token = alice_login.json()["access_token"]

    # Alice tries to create product -> 403 Forbidden
    cust_res = await async_client.post(
        "/api/v1/admin/products",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "name": "Unauthorized Gadget",
            "slug": "unauthorized-gadget",
            "description": "Should fail",
            "category": "Accessories",
            "price": 99.0,
            "stock": 5,
        },
    )
    assert cust_res.status_code == 403

    # Admin token
    admin_login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "admin@cybershield.io", "password": "AdminPass123!"},
    )
    admin_token = admin_login.json()["access_token"]

    # Admin creates product -> 201 Created
    admin_res = await async_client.post(
        "/api/v1/admin/products",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Hardware Security Dongle",
            "slug": "hardware-security-dongle",
            "description": "Authorized admin product",
            "category": "Hardware Security",
            "price": 120.0,
            "stock": 10,
        },
    )
    assert admin_res.status_code == 201
    assert admin_res.json()["name"] == "Hardware Security Dongle"
