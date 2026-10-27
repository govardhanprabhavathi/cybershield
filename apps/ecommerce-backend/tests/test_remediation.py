"""Test suite for Phase 9: AI-Driven Automated Remediation, AST Patch Drafting, and Sandbox Verification."""

from pathlib import Path

import pytest
from app.core.database import get_session_maker
from httpx import AsyncClient

from agents.remediation.remediation_agent import RemediationAgent
from agents.verification.verification_agent import VerificationAgent
from security.remediation_engine.ast_patcher import ASTPatchGenerator
from security.remediation_engine.sandbox import RemediationSandbox
from security.schemas.correlation import TriangulatedDossier
from security.schemas.remediation import DraftRemediationRequest
from services.remediation.remediation_service import RemediationService


def test_ast_patch_generation_sqli():
    """Verify ASTPatchGenerator replaces string interpolation with parameterized queries for CWE-89."""
    patcher = ASTPatchGenerator()
    target_file = "apps/ecommerce-backend/app/services/product_service.py"

    diff = patcher.generate_patch(file_path=target_file, cwe_id="CWE-89")

    assert diff.strategy == "PARAMETERIZATION"
    assert diff.file_path == target_file
    assert ":term" in diff.patched_code
    assert "LIMIT :limit OFFSET :offset" in diff.patched_code
    assert diff.unified_diff.startswith("--- a/product_service.py")
    assert "+" in diff.unified_diff
    assert "-" in diff.unified_diff


def test_ast_patch_generation_bola_and_business_flow():
    """Verify ASTPatchGenerator enforces tenant isolation gates and positive input bounds."""
    patcher = ASTPatchGenerator()

    # 1. BOLA / IDOR (CWE-284)
    order_file = "apps/ecommerce-backend/app/services/order_service.py"
    bola_diff = patcher.generate_patch(file_path=order_file, cwe_id="CWE-284")
    assert bola_diff.strategy == "AUTHORIZATION_GATE"
    assert "not settings.ENABLE_VULNERABILITY_BOLA" in bola_diff.original_code
    assert "not settings.ENABLE_VULNERABILITY_BOLA" not in bola_diff.patched_code
    assert "order.user_id != current_user.id and current_user.role != \"admin\"" in bola_diff.patched_code

    # 2. Business Flow Abuse (CWE-840)
    cart_file = "apps/ecommerce-backend/app/services/cart_service.py"
    biz_diff = patcher.generate_patch(file_path=cart_file, cwe_id="CWE-840")
    assert biz_diff.strategy == "INPUT_VALIDATION"
    assert "not settings.ENABLE_VULNERABILITY_BUSINESS_FLOW" in biz_diff.original_code
    assert "not settings.ENABLE_VULNERABILITY_BUSINESS_FLOW" not in biz_diff.patched_code
    assert "if item_in.quantity <= 0:" in biz_diff.patched_code


def test_sandbox_syntax_verification_and_error_handling():
    """Verify RemediationSandbox detects syntax errors, checks safety invariants, and flags regressions."""
    sandbox = RemediationSandbox()

    # Valid syntax
    valid_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    ok, msg = sandbox.verify_syntax(valid_code)
    assert ok is True
    assert "zero syntax errors" in msg

    # Broken syntax
    broken_code = "def broken(a, b\n    return a +"
    broken_ok, broken_msg = sandbox.verify_syntax(broken_code)
    assert broken_ok is False
    assert "SyntaxError" in broken_msg

    # AST Safety: Unsafe raw f-string inside text()
    unsafe_sql_code = 'from sqlalchemy import text\ndef run(s):\n    return text(f"SELECT * FROM p WHERE name = \'{s}\'")\n'
    safety_ok, safety_msg = sandbox.verify_ast_safety(unsafe_sql_code, "CWE-89")
    assert safety_ok is False
    assert "JoinedStr" in safety_msg

    # AST Safety: Parameterized text() is safe
    safe_sql_code = 'from sqlalchemy import text\ndef run(s):\n    return text("SELECT * FROM p WHERE name = :s")\n'
    safe_ok, _ = sandbox.verify_ast_safety(safe_sql_code, "CWE-89")
    assert safe_ok is True

    # Non-regression detection
    orig = "def func_a(): pass\ndef func_b(): pass\n"
    patched_missing = "def func_a(): pass\n"
    regr_ok, regr_msg = sandbox.verify_no_regression(orig, patched_missing)
    assert regr_ok is False
    assert "func_b" in regr_msg


@pytest.mark.asyncio
async def test_agent10_and_agent11_end_to_end_verification():
    """Verify Agent 10 drafts proposal from dossier and Agent 11 validates syntax and replays exploit."""
    agent10 = RemediationAgent()
    agent11 = VerificationAgent()

    dossier = TriangulatedDossier(
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        vulnerability_title="SQL Injection on Product Search",
        endpoint="/api/v1/products",
        file_path="apps/ecommerce-backend/app/services/product_service.py",
        line_number=28,
    )

    proposal = agent10.draft_patch_from_dossier(dossier)
    assert proposal.cwe_id == "CWE-89"
    assert proposal.status == "DRAFTED"
    assert proposal.diff.strategy == "PARAMETERIZATION"

    report = await agent11.verify_proposal(proposal)
    assert report.status == "VERIFIED"
    assert report.syntax_valid is True
    assert report.exploit_neutralized is True
    assert len(report.checks) >= 3
    assert len(report.replay_results) >= 1
    assert report.replay_results[0].probe_name == "SQLI_PARAMETERIZATION_REPLAY"


@pytest.mark.asyncio
async def test_remediation_service_lifecycle_apply_and_rollback(tmp_path: Path):
    """Verify RemediationService database lifecycle: drafting, verifying, disk commit, and zero-downtime rollback."""
    test_file = tmp_path / "mock_service.py"
    original_code = (
        'from app.core.config import get_settings\n'
        'settings = get_settings()\n\n'
        'class MockService:\n'
        '    def search(term):\n'
        '        # SQL Injection Toggle Check on Search Parameter\n'
        '        if filters.search and settings.ENABLE_VULNERABILITY_SQLI:\n'
        '            # Controlled Flaw: Direct string interpolation into raw SQL query\n'
        '            # Allows demonstration of UNION-based, boolean-based, or error-based SQLi\n'
        '            raw_sql = f"SELECT id, name, slug, description, category, price, stock, is_active, created_at, updated_at FROM products WHERE is_active = 1 AND (name LIKE \'%{filters.search}%\' OR description LIKE \'%{filters.search}%\') LIMIT {limit} OFFSET {filters.offset}"\n'
        '            try:\n'
        '                result = await db.execute(text(raw_sql))\n'
        '                rows = result.mappings().all()\n'
        '                products = []\n'
        '                for row in rows:\n'
        '                    products.append(Product(**row))\n'
        '                return products\n'
        '            except Exception as exc:\n'
        '                # Controlled error leak when SQL syntax is broken by injection payload\n'
        '                raise HTTPException(\n'
        '                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,\n'
        '                    detail=f"Database execution error: {exc}",\n'
        '                ) from exc\n'
    )
    test_file.write_text(original_code, encoding="utf-8")

    session_maker = await get_session_maker()
    async with session_maker() as session:
        service = RemediationService()

        # 1. Draft proposal targeting mock file
        record = await service.draft_proposal(
            session,
            DraftRemediationRequest(
                cwe_id="CWE-89",
                target_file=str(test_file),
            ),
        )
        assert record.id.startswith("REM-")
        assert record.status == "DRAFTED"

        # 2. Verify proposal
        verified_record = await service.verify_proposal(session, record.id)
        assert verified_record is not None
        assert verified_record.status == "VERIFIED"
        assert verified_record.verification_report["syntax_valid"] is True

        # 3. Apply proposal to disk
        applied_record = await service.apply_proposal(session, record.id)
        assert applied_record is not None
        assert applied_record.status == "APPLIED"

        # Confirm file on disk now has patched code
        disk_content = test_file.read_text(encoding="utf-8")
        assert ":term" in disk_content

        # 4. Roll back proposal
        rollback_record = await service.rollback_proposal(session, record.id)
        assert rollback_record is not None
        assert rollback_record.status == "ROLLED_BACK"

        # Confirm file on disk restored to original code
        restored_content = test_file.read_text(encoding="utf-8")
        assert "raw_sql = f\"SELECT" in restored_content


@pytest.mark.asyncio
async def test_remediation_rest_api_endpoints(async_client: AsyncClient):
    """End-to-end integration test verifying complete REST API workflow for automated remediation."""
    # 1. Draft proposal via API
    draft_res = await async_client.post(
        "/security/v1/remediation/draft",
        json={"cwe_id": "CWE-89"},
    )
    assert draft_res.status_code == 201
    proposal = draft_res.json()
    proposal_id = proposal["proposal_id"]
    assert proposal_id.startswith("REM-")
    assert proposal["cwe_id"] == "CWE-89"
    assert proposal["status"] == "DRAFTED"
    assert "diff" in proposal

    # 2. List proposals
    list_res = await async_client.get("/security/v1/remediation/proposals")
    assert list_res.status_code == 200
    proposals_list = list_res.json()
    assert len(proposals_list) >= 1

    # Filter by CWE
    filter_res = await async_client.get("/security/v1/remediation/proposals?cwe_id=CWE-89")
    assert filter_res.status_code == 200
    assert len(filter_res.json()) >= 1

    # 3. Retrieve single proposal
    get_res = await async_client.get(f"/security/v1/remediation/proposals/{proposal_id}")
    assert get_res.status_code == 200
    assert get_res.json()["proposal_id"] == proposal_id

    # 4. Verify proposal via API
    verify_res = await async_client.post(f"/security/v1/remediation/proposals/{proposal_id}/verify")
    assert verify_res.status_code == 200
    verified_data = verify_res.json()
    assert verified_data["status"] == "VERIFIED"
    assert verified_data["verification_report"] is not None
    assert verified_data["verification_report"]["syntax_valid"] is True
    assert verified_data["verification_report"]["exploit_neutralized"] is True

    # 5. Apply proposal with dry_run=True (preview)
    dry_res = await async_client.post(f"/security/v1/remediation/proposals/{proposal_id}/apply?dry_run=true")
    assert dry_res.status_code == 200

    # 6. Query nonexistent proposal returns 404
    missing_res = await async_client.get("/security/v1/remediation/proposals/REM-NONEXISTENT")
    assert missing_res.status_code == 404
