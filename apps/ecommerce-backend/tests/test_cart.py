import pytest
from app.core.config import get_settings
from httpx import AsyncClient


@pytest.fixture
async def alice_auth_headers(async_client: AsyncClient):
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "alice@cybershield.io", "password": "AlicePass123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_get_cart_and_add_item(async_client: AsyncClient, alice_auth_headers: dict):
    # Get available product
    prod_res = await async_client.get("/api/v1/products")
    product = prod_res.json()[0]

    # Clear cart first
    await async_client.delete("/api/v1/cart", headers=alice_auth_headers)

    # Empty cart check
    cart_res = await async_client.get("/api/v1/cart", headers=alice_auth_headers)
    assert cart_res.status_code == 200
    assert cart_res.json()["total_items"] == 0
    assert cart_res.json()["subtotal"] == 0.0

    # Add item
    add_res = await async_client.post(
        "/api/v1/cart/items",
        headers=alice_auth_headers,
        json={"product_id": product["id"], "quantity": 2},
    )
    assert add_res.status_code == 201
    assert add_res.json()["quantity"] == 2
    assert add_res.json()["total_price"] == round(product["price"] * 2, 2)

    # Verify cart summary
    summary_res = await async_client.get("/api/v1/cart", headers=alice_auth_headers)
    assert summary_res.json()["total_items"] == 2
    assert summary_res.json()["subtotal"] == round(product["price"] * 2, 2)


@pytest.mark.asyncio
async def test_update_and_remove_cart_item(async_client: AsyncClient, alice_auth_headers: dict):
    # Add product
    prod_res = await async_client.get("/api/v1/products")
    product_id = prod_res.json()[0]["id"]

    add_res = await async_client.post(
        "/api/v1/cart/items",
        headers=alice_auth_headers,
        json={"product_id": product_id, "quantity": 1},
    )
    item_id = add_res.json()["id"]

    # Update quantity to 4
    patch_res = await async_client.patch(
        f"/api/v1/cart/items/{item_id}",
        headers=alice_auth_headers,
        json={"quantity": 4},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["quantity"] == 4

    # Remove item
    del_res = await async_client.delete(
        f"/api/v1/cart/items/{item_id}",
        headers=alice_auth_headers,
    )
    assert del_res.status_code == 200


@pytest.mark.asyncio
async def test_business_flow_abuse_toggle(async_client: AsyncClient, alice_auth_headers: dict):
    settings = get_settings()
    prod_res = await async_client.get("/api/v1/products")
    product_id = prod_res.json()[0]["id"]

    # 1. When vulnerability is disabled: negative quantity rejected with 400
    settings.ENABLE_VULNERABILITY_BUSINESS_FLOW = False
    safe_attempt = await async_client.post(
        "/api/v1/cart/items",
        headers=alice_auth_headers,
        json={"product_id": product_id, "quantity": -2},
    )
    assert safe_attempt.status_code == 400
    assert "positive integer" in safe_attempt.json()["detail"].lower()

    # 2. When vulnerability is enabled: negative quantity accepted
    settings.ENABLE_VULNERABILITY_BUSINESS_FLOW = True
    vulnerable_attempt = await async_client.post(
        "/api/v1/cart/items",
        headers=alice_auth_headers,
        json={"product_id": product_id, "quantity": -2},
    )
    assert vulnerable_attempt.status_code == 201
    assert vulnerable_attempt.json()["quantity"] == -2
