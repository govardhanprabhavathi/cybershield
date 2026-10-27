"""Legitimate User Simulator emulating realistic customer browsing, cart management, and checkout flows."""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from httpx import AsyncClient


@dataclass
class UserSimulationResult:
    """Telemetry and health metrics captured during a simulated customer session."""

    session_id: str
    email: str
    client_ip: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    status_codes: list[int] = field(default_factory=list)
    latencies_ms: list[float] = field(default_factory=list)
    is_preserved: bool = True
    errors: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 1.0
        return round(self.successful_requests / self.total_requests, 4)


class LegitimateUserSimulator:
    """Executes authentic customer behaviors with realistic request headers and state management."""

    def __init__(
        self,
        client: AsyncClient,
        email: str | None = None,
        password: str = "CustomerPass123!",
        client_ip: str = "127.0.0.1",
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberShield-Shopper/1.0",
    ):
        self.client = client
        self.email = email or f"shopper_{uuid.uuid4().hex[:8]}@cybershield.io"
        self.password = password
        self.client_ip = client_ip
        self.user_agent = user_agent
        self.token: str | None = None
        self.session_id: str = str(uuid.uuid4())
        self.user_id: str | None = None
        self.result = UserSimulationResult(
            session_id=self.session_id,
            email=self.email,
            client_ip=self.client_ip,
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "X-Forwarded-For": self.client_ip,
            "User-Agent": self.user_agent,
            "X-Session-ID": self.session_id,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _send_request(self, method: str, url: str, **kwargs) -> Any:
        headers = self._headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        start = time.perf_counter()
        self.result.total_requests += 1

        try:
            res = await self.client.request(method, url, headers=headers, **kwargs)
            duration_ms = (time.perf_counter() - start) * 1000.0
            self.result.latencies_ms.append(round(duration_ms, 2))
            self.result.status_codes.append(res.status_code)

            # Update session ID if server provided one
            server_sid = res.headers.get("X-Session-ID")
            if server_sid:
                self.session_id = server_sid
                self.result.session_id = server_sid

            if res.status_code in (200, 201):
                self.result.successful_requests += 1
            else:
                self.result.failed_requests += 1
                if res.status_code in (401, 403):
                    self.result.is_preserved = False
                self.result.errors.append(f"{method} {url} returned HTTP {res.status_code}")

            return res
        except Exception as exc:  # noqa: BLE001
            duration_ms = (time.perf_counter() - start) * 1000.0
            self.result.latencies_ms.append(round(duration_ms, 2))
            self.result.failed_requests += 1
            self.result.is_preserved = False
            self.result.errors.append(f"{method} {url} failed with exception: {exc}")
            return None

    async def register_and_login(self) -> bool:
        """Register customer account and establish authenticated session."""
        reg_res = await self._send_request(
            "POST",
            "/api/v1/auth/register",
            json={
                "email": self.email,
                "password": self.password,
                "full_name": "Legitimate Shopper",
            },
        )
        # If already registered, proceed to login
        if reg_res is None or reg_res.status_code not in (201, 400):
            return False

        login_res = await self._send_request(
            "POST",
            "/api/v1/auth/login",
            json={"email": self.email, "password": self.password},
        )
        if login_res and login_res.status_code == 200:
            data = login_res.json()
            self.token = data.get("access_token")
            self.session_id = data.get("session_id", self.session_id)
            self.result.session_id = self.session_id
            return True
        return False

    async def browse_catalog(self) -> list[dict[str, Any]]:
        """Fetch product list from store."""
        res = await self._send_request("GET", "/api/v1/products")
        if res and res.status_code == 200:
            return res.json()
        return []

    async def search_products(self, query: str = "Laptop") -> list[dict[str, Any]]:
        """Execute benign search query."""
        res = await self._send_request("GET", f"/api/v1/products?search={query}")
        if res and res.status_code == 200:
            return res.json()
        return []

    async def add_to_cart(self, product_id: str, quantity: int = 1) -> bool:
        """Add product to customer cart."""
        res = await self._send_request(
            "POST",
            "/api/v1/cart/items",
            json={"product_id": product_id, "quantity": quantity},
        )
        return res is not None and res.status_code in (200, 201)

    async def view_cart(self) -> dict[str, Any] | None:
        """View current cart contents."""
        res = await self._send_request("GET", "/api/v1/cart")
        if res and res.status_code == 200:
            return res.json()
        return None

    async def checkout_and_pay(self) -> bool:
        """Convert cart items to an order and settle payment."""
        order_res = await self._send_request(
            "POST",
            "/api/v1/orders",
            json={"shipping_address": "456 Market St, San Francisco, CA"},
        )
        if not order_res or order_res.status_code != 201:
            return False

        order_data = order_res.json()
        order_id = order_data.get("id")
        if not order_id:
            return False

        pay_res = await self._send_request(
            "POST",
            "/api/v1/orders/checkout/pay",
            json={"order_id": order_id, "payment_method": "credit_card"},
        )
        return pay_res is not None and pay_res.status_code == 200

    async def view_orders(self) -> list[dict[str, Any]]:
        """View own historical orders."""
        res = await self._send_request("GET", "/api/v1/orders")
        if res and res.status_code == 200:
            return res.json()
        return []

    async def view_profile(self) -> Any:
        """Verify session authentication health via /me endpoint."""
        return await self._send_request("GET", "/api/v1/auth/me")

    async def run_shopping_journey(self) -> UserSimulationResult:
        """Execute a full, realistic end-to-end shopping journey."""
        # 1. Register & Login
        logged_in = await self.register_and_login()
        if not logged_in:
            return self.result

        # 2. Browse products
        products = await self.browse_catalog()

        # 3. Search catalog
        await self.search_products(query="laptop")
        await self.search_products(query="phone")

        # 4. View profile
        await self.view_profile()

        # 5. Add product to cart and checkout if products available
        if products:
            first_prod_id = products[0]["id"]
            await self.add_to_cart(product_id=first_prod_id, quantity=1)
            await self.view_cart()
            await self.checkout_and_pay()
            await self.view_orders()

        # 6. Final preservation check
        await self.view_profile()

        return self.result
