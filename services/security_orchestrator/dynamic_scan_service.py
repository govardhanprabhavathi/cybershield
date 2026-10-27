"""DAST Dynamic Scan Orchestrator running Agent 3 probes and performing SAST-DAST correlation."""

from datetime import UTC, datetime

import httpx
from app.models.finding import SecurityFindingRecord
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.api_security.api_security_agent import APISecurityAgent
from security.schemas.findings import DynamicScanReport, ProbeResult, SecurityFinding


class DynamicScanService:
    """Orchestrator for dynamic vulnerability probing and pre-deployment evidence correlation."""

    @staticmethod
    async def run_dynamic_scan(
        db: AsyncSession,
        client: httpx.AsyncClient,
        app: FastAPI,
        persist_to_db: bool = True,
    ) -> DynamicScanReport:
        api_agent = APISecurityAgent(client=client, app=app)
        probe_results: list[ProbeResult] = []
        confirmed_findings: list[SecurityFinding] = []

        # 1. Prerequisite Authentication Setup (Alice = victim, Bob = attacker)
        alice_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@cybershield.io", "password": "AlicePass123!"},
        )
        bob_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "bob@cybershield.io", "password": "BobPass123!"},
        )

        alice_token = alice_login.json().get("access_token") if alice_login.status_code == 200 else ""
        bob_token = bob_login.json().get("access_token") if bob_login.status_code == 200 else ""

        # Fetch victim order and catalog product for targeted probing
        alice_order_id = ""
        sample_product_id = ""

        if alice_token:
            orders_res = await client.get(
                "/api/v1/orders",
                headers={"Authorization": f"Bearer {alice_token}"},
            )
            if orders_res.status_code == 200:
                orders_list = orders_res.json()
                if orders_list:
                    alice_order_id = orders_list[0].get("id", "")

        products_res = await client.get("/api/v1/products?limit=1")
        if products_res.status_code == 200:
            products_list = products_res.json()
            if products_list:
                sample_product_id = products_list[0].get("id", "")

        # 2. Execute Probe 1: BOLA / IDOR on Orders
        if alice_token and bob_token and alice_order_id:
            bola_result = await api_agent.probe_bola(
                victim_token=alice_token,
                attacker_token=bob_token,
                victim_order_id=alice_order_id,
            )
            probe_results.append(bola_result)
            if bola_result.vulnerable and bola_result.finding:
                confirmed_findings.append(bola_result.finding)

        # 3. Execute Probe 2: SQL Injection on Products Search
        sqli_result = await api_agent.probe_sqli("/api/v1/products")
        probe_results.append(sqli_result)
        if sqli_result.vulnerable and sqli_result.finding:
            confirmed_findings.append(sqli_result.finding)

        # 4. Execute Probe 3: Sensitive Business Flow on Cart
        if alice_token and sample_product_id:
            biz_result = await api_agent.probe_business_flow(
                user_token=alice_token,
                product_id=sample_product_id,
            )
            probe_results.append(biz_result)
            if biz_result.vulnerable and biz_result.finding:
                confirmed_findings.append(biz_result.finding)

        # 5. Execute Probe 4: Resource Consumption on Products
        resource_result = await api_agent.probe_resource_consumption("/api/v1/products")
        probe_results.append(resource_result)
        if resource_result.vulnerable and resource_result.finding:
            confirmed_findings.append(resource_result.finding)

        # 6. Execute OpenAPI Contract Audit
        contract_status, contract_issues = api_agent.audit_openapi_contract(app)

        # 7. Pre-Deployment SAST-DAST Correlation & Database Persistence
        confirmed_sast_count = 0
        if persist_to_db:
            for f in confirmed_findings:
                # Find matching static code finding
                stmt = select(SecurityFindingRecord).where(
                    SecurityFindingRecord.category == f.category,
                    SecurityFindingRecord.endpoint == f.endpoint,
                )
                existing = (await db.execute(stmt)).scalars().first()

                if existing:
                    # Correlate: upgrade SAST finding status to CONFIRMED
                    existing.status = "CONFIRMED"
                    existing.confidence = max(existing.confidence, f.confidence)
                    updated_evidence = dict(existing.raw_evidence)
                    updated_evidence["dast_confirmation"] = f.raw_evidence
                    existing.raw_evidence = updated_evidence
                    confirmed_sast_count += 1
                else:
                    # Store new dynamic finding
                    record = SecurityFindingRecord(
                        id=f.finding_id,
                        agent_source=f.agent_source,
                        category=f.category,
                        cwe_id=f.cwe_id,
                        owasp_category=f.owasp_category,
                        severity=f.severity,
                        confidence=f.confidence,
                        title=f.title,
                        description=f.description,
                        file_path=f.file_path,
                        line_number=f.line_number,
                        endpoint=f.endpoint,
                        method=f.method,
                        parameter=f.parameter,
                        raw_evidence=f.raw_evidence,
                        remediation_guidance=f.remediation_guidance,
                        status=f.status,
                        created_at=f.created_at,
                    )
                    db.add(record)

            await db.commit()

        vulnerabilities_confirmed = sum(1 for p in probe_results if p.vulnerable)

        return DynamicScanReport(
            timestamp=datetime.now(UTC),
            probes_executed=len(probe_results),
            vulnerabilities_confirmed=vulnerabilities_confirmed,
            probes=probe_results,
            findings=confirmed_findings,
            confirmed_sast_count=confirmed_sast_count,
            openapi_conformance_status=contract_status,
            openapi_issues=contract_issues,
        )
