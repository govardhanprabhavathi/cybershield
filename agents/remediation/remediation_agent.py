"""Agent 10: Remediation Agent responsible for drafting AST code patches and unified diffs."""

from pathlib import Path

from app.models.finding import SecurityFindingRecord

from security.remediation_engine.ast_patcher import ASTPatchGenerator
from security.schemas.correlation import TriangulatedDossier
from security.schemas.remediation import RemediationProposal


class RemediationAgent:
    """Automates vulnerability remediation by generating syntax-safe AST patches and unified diffs."""

    def __init__(self):
        self.patcher = ASTPatchGenerator()

    @staticmethod
    def resolve_default_file_for_cwe(cwe_id: str, endpoint: str | None = None) -> str:
        """Resolve primary codebase file path for common CWE classifications."""
        cwe = cwe_id.upper().strip()
        if cwe == "CWE-89":
            return "apps/ecommerce-backend/app/services/product_service.py"
        elif cwe in ("CWE-284", "CWE-639"):
            return "apps/ecommerce-backend/app/services/order_service.py"
        elif cwe in ("CWE-840", "CWE-20"):
            return "apps/ecommerce-backend/app/services/cart_service.py"
        elif cwe in ("CWE-798", "CWE-259"):
            return "apps/ecommerce-backend/app/core/config.py"

        if endpoint:
            if "product" in endpoint:
                return "apps/ecommerce-backend/app/services/product_service.py"
            elif "order" in endpoint:
                return "apps/ecommerce-backend/app/services/order_service.py"
            elif "cart" in endpoint:
                return "apps/ecommerce-backend/app/services/cart_service.py"

        return "apps/ecommerce-backend/app/services/product_service.py"

    def draft_patch_from_dossier(self, dossier: TriangulatedDossier) -> RemediationProposal:
        """Synthesize candidate remediation proposal from a Phase 8 TriangulatedDossier."""
        target_file = dossier.file_path or self.resolve_default_file_for_cwe(
            dossier.cwe_id, dossier.endpoint
        )

        # Normalize file path
        if not Path(target_file).is_file() and not (Path.cwd() / target_file).is_file():
            target_file = self.resolve_default_file_for_cwe(dossier.cwe_id, dossier.endpoint)

        diff = self.patcher.generate_patch(file_path=target_file, cwe_id=dossier.cwe_id)

        return RemediationProposal(
            dossier_id=dossier.dossier_id,
            cwe_id=dossier.cwe_id,
            vulnerability_title=dossier.vulnerability_title,
            target_file=target_file,
            diff=diff,
            status="DRAFTED",
        )

    def draft_patch_from_finding(self, finding: SecurityFindingRecord) -> RemediationProposal:
        """Synthesize candidate remediation proposal from a stored SecurityFindingRecord."""
        target_file = finding.file_path or self.resolve_default_file_for_cwe(
            finding.cwe_id, finding.endpoint
        )

        if not Path(target_file).is_file() and not (Path.cwd() / target_file).is_file():
            target_file = self.resolve_default_file_for_cwe(finding.cwe_id, finding.endpoint)

        diff = self.patcher.generate_patch(file_path=target_file, cwe_id=finding.cwe_id)

        return RemediationProposal(
            finding_id=finding.id,
            cwe_id=finding.cwe_id,
            vulnerability_title=finding.title,
            target_file=target_file,
            diff=diff,
            status="DRAFTED",
        )

    def draft_patch(
        self,
        cwe_id: str,
        target_file: str | None = None,
        title: str = "",
        dossier_id: str | None = None,
        finding_id: str | None = None,
    ) -> RemediationProposal:
        """Direct programmatic entrypoint to draft a patch."""
        resolved_file = target_file or self.resolve_default_file_for_cwe(cwe_id)
        diff = self.patcher.generate_patch(file_path=resolved_file, cwe_id=cwe_id)

        return RemediationProposal(
            dossier_id=dossier_id,
            finding_id=finding_id,
            cwe_id=cwe_id,
            vulnerability_title=title or f"Automated Remediation for {cwe_id}",
            target_file=resolved_file,
            diff=diff,
            status="DRAFTED",
        )
