import pytest
from app.core.config import get_settings
from httpx import AsyncClient


@pytest.fixture
async def alice_token(async_client: AsyncClient):
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "alice@cybershield.io", "password": "AlicePass123!"},
    )
    return login.json()["access_token"]


@pytest.fixture
async def bob_token(async_client: AsyncClient):
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "bob@cybershield.io", "password": "BobPass123!"},
    )
    return login.json()["access_token"]


@pytest.mark.asyncio
async def test_create_order_and_checkout(async_client: AsyncClient, alice_token: str):
    headers = {"Authorization": f"Bearer {alice_token}"}

    # Add item to cart
    prod_res = await async_client.get("/api/v1/products")
    product_id = prod_res.json()[0]["id"]
    await async_client.post(
        "/api/v1/cart/items",
        headers=headers,
        json={"product_id": product_id, "quantity": 1},
    )

    # Place order
    order_res = await async_client.post(
        "/api/v1/orders",
        headers=headers,
        json={"shipping_address": "742 Evergreen Terrace, Springfield"},
    )
    assert order_res.status_code == 201
    order_data = order_res.json()
    assert order_data["status"] == "pending"
    assert len(order_data["items"]) == 1
    assert order_data["shipping_address"] == "742 Evergreen Terrace, Springfield"
    order_id = order_data["id"]

    # Settle payment
    pay_res = await async_client.post(
        "/api/v1/orders/checkout/pay",
        headers=headers,
        json={"order_id": order_id, "payment_method": "credit_card"},
    )
    assert pay_res.status_code == 200
    assert pay_res.json()["status"] == "success"

    # Verify order is now paid
    updated_order = await async_client.get(f"/api/v1/orders/{order_id}", headers=headers)
    assert updated_order.status_code == 200
    assert updated_order.json()["status"] == "paid"
    assert updated_order.json()["payment_status"] == "success"


@pytest.mark.asyncio
async def test_bola_idor_vulnerability_toggle(
    async_client: AsyncClient, alice_token: str, bob_token: str
):
    settings = get_settings()
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    bob_headers = {"Authorization": f"Bearer {bob_token}"}

    # Retrieve Alice's orders to obtain Alice's order ID
    alice_orders = await async_client.get("/api/v1/orders", headers=alice_headers)
    assert alice_orders.status_code == 200
    alice_order_id = alice_orders.json()[0]["id"]

    # 1. When BOLA vulnerability is enabled (flaw present): Bob can view Alice's order
    settings.ENABLE_VULNERABILITY_BOLA = True
    vulnerable_res = await async_client.get(f"/api/v1/orders/{alice_order_id}", headers=bob_headers)
    assert vulnerable_res.status_code == 200
    assert vulnerable_res.json()["id"] == alice_order_id

    # 2. When BOLA vulnerability is disabled (safe tenant isolation enforced): Bob is blocked
    settings.ENABLE_VULNERABILITY_BOLA = False
    safe_res = await async_client.get(f"/api/v1/orders/{alice_order_id}", headers=bob_headers)
    assert safe_res.status_code == 403
    assert "permission" in safe_res.json()["detail"].lower()
