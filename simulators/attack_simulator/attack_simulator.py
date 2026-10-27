"""Multi-vector concurrent attack simulator emulating targeted cyber attacks against e-commerce APIs."""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from httpx import AsyncClient


@dataclass
class AttackSimulationResult:
    """Metrics and containment status captured during an adversary simulation campaign."""

    session_id: str
    persona: str
    client_ip: str
    total_probes: int = 0
    status_codes: list[int] = field(default_factory=list)
    latencies_ms: list[float] = field(default_factory=list)
    is_contained: bool = False
    containment_request_index: int | None = None
    detected_attack_types: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class AttackSimulator:
    """Executes multi-vector cyber attack campaigns to evaluate detection and graduated containment."""

    def __init__(
        self,
        client: AsyncClient,
        persona: str = "MULTI_VECTOR",
        client_ip: str = "198.51.100.5",
        user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) CyberShield-AdversaryBot/2.1",
        email: str | None = None,
        password: str = "AttackerPass123!",
    ):
        self.client = client
        self.persona = persona.upper()
        self.client_ip = client_ip
        self.user_agent = user_agent
        self.email = email or f"attacker_{uuid.uuid4().hex[:8]}@cybershield.io"
        self.password = password
        self.token: str | None = None
        self.session_id: str = str(uuid.uuid4())
        self.result = AttackSimulationResult(
            session_id=self.session_id,
            persona=self.persona,
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

    async def _send_probe(self, method: str, url: str, **kwargs) -> Any:
        headers = self._headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        start = time.perf_counter()
        self.result.total_probes += 1

        try:
            res = await self.client.request(method, url, headers=headers, **kwargs)
            duration_ms = (time.perf_counter() - start) * 1000.0
            self.result.latencies_ms.append(round(duration_ms, 2))
            self.result.status_codes.append(res.status_code)

            # Check if this probe triggered containment rejection
            if res.status_code == 403:
                detail = ""
                try:
                    detail = res.json().get("detail", "")
                except (ValueError, AttributeError):
                    detail = ""
                if "contained" in detail.lower() or not self.result.is_contained:
                    self.result.is_contained = True
                    if self.result.containment_request_index is None:
                        self.result.containment_request_index = self.result.total_probes

            return res
        except Exception as exc:  # noqa: BLE001
            duration_ms = (time.perf_counter() - start) * 1000.0
            self.result.latencies_ms.append(round(duration_ms, 2))
            self.result.errors.append(f"{method} {url} error: {exc}")
            return None

    async def register_and_login(self) -> bool:
        """Establish attacker account and authenticated session for authorized-path attacks."""
        await self._send_probe(
            "POST",
            "/api/v1/auth/register",
            json={
                "email": self.email,
                "password": self.password,
                "full_name": "Adversary Persona",
            },
        )
        login_res = await self._send_probe(
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

    async def run_sqli_attack(self) -> None:
        """Execute automated SQL injection probes against catalog search."""
        payloads = [
            "laptop' OR '1'='1--",
            "phone' UNION SELECT id, email, hashed_password FROM users--",
            "tablet'; DROP TABLE orders--",
            "item' OR 1=1#",
        ]
        for p in payloads:
            await self._send_probe("GET", f"/api/v1/products?search={p}")
        self.result.detected_attack_types.append("SQL_INJECTION")

    async def run_bola_attack(self) -> None:
        """Execute BOLA / IDOR cross-tenant order enumeration probes."""
        for target_id in ("order-101", "order-102", "order-103", "order-104"):
            await self._send_probe("GET", f"/api/v1/orders/{target_id}")
        self.result.detected_attack_types.append("BOLA_IDOR")

    async def run_brute_force_attack(self, count: int = 6) -> None:
        """Execute credential stuffing brute-force authentication attempts."""
        for i in range(count):
            await self._send_probe(
                "POST",
                "/api/v1/auth/login",
                json={
                    "email": "victim_admin@cybershield.io",
                    "password": f"WrongPasswordGuess_{i}",
                },
            )
        self.result.detected_attack_types.append("BRUTE_FORCE_AUTH")

    async def run_business_flow_attack(self) -> None:
        """Execute business logic manipulation (negative cart quantities)."""
        await self._send_probe(
            "POST",
            "/api/v1/cart/items",
            json={"product_id": "test-prod-1", "quantity": -99},
        )
        self.result.detected_attack_types.append("BUSINESS_FLOW_ABUSE")

    async def run_resource_consumption_attack(self) -> None:
        """Execute algorithmic complexity and resource consumption query floods."""
        await self._send_probe("GET", "/api/v1/products?limit=5000")
        self.result.detected_attack_types.append("RESOURCE_CONSUMPTION")

    async def run_multi_vector_attack(self) -> None:
        """Execute correlated multi-vector campaign (SQLi followed by BOLA order enumeration)."""
        await self.run_sqli_attack()
        await self.run_bola_attack()

    async def execute(self) -> AttackSimulationResult:
        """Execute the configured attacker persona campaign."""
        # 1. Establish initial authenticated session if required
        await self.register_and_login()

        # 2. Execute persona vector
        if self.persona == "SQL_INJECTION":
            await self.run_sqli_attack()
        elif self.persona == "BOLA_IDOR":
            await self.run_bola_attack()
        elif self.persona == "BRUTE_FORCE":
            await self.run_brute_force_attack()
        elif self.persona == "BUSINESS_FLOW":
            await self.run_business_flow_attack()
        elif self.persona == "RESOURCE_CONSUMPTION":
            await self.run_resource_consumption_attack()
        elif self.persona == "MULTI_VECTOR":
            await self.run_multi_vector_attack()
        else:
            await self.run_multi_vector_attack()

        return self.result
