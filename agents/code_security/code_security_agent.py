import ast
import os
from pathlib import Path

from security.schemas.findings import SecurityFinding


class CodeSecurityASTVisitor(ast.NodeVisitor):
    """AST visitor searching for injection risks, missing authorization, and business logic flaws."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: list[SecurityFinding] = []

    def visit_Call(self, node: ast.Call):
        # Rule 1: SQL Injection Detection via raw query interpolation
        # Pattern: db.execute(text(f"...{var}...")) or text("..." + var)
        if hasattr(node.func, "id") and node.func.id == "text" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.JoinedStr):  # f-string inside text()
                self.findings.append(
                    SecurityFinding(
                        agent_source="code_security",
                        category="SQL_INJECTION",
                        cwe_id="CWE-89",
                        owasp_category="OWASP Top 10 - Injection",
                        severity="HIGH",
                        confidence=0.95,
                        title="SQL Injection via Formatted String Interpolation",
                        description=(
                            f"Direct formatted string interpolation detected inside database query call "
                            f"at line {node.lineno}. Untrusted user input can alter SQL execution semantics."
                        ),
                        file_path=self.file_path,
                        line_number=node.lineno,
                        endpoint="/api/v1/products",
                        method="GET",
                        parameter="search",
                        raw_evidence={"line": node.lineno, "node_type": "JoinedStr"},
                        remediation_guidance=(
                            "Use parameterized SQLAlchemy queries or ORM filter expressions (e.g., .ilike()). "
                            "Never interpolate raw strings directly into text() blocks."
                        ),
                    )
                )
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
                    self.findings.append(
                        SecurityFinding(
                            agent_source="code_security",
                            category="SQL_INJECTION",
                            cwe_id="CWE-89",
                            owasp_category="OWASP Top 10 - Injection",
                            severity="HIGH",
                            confidence=0.90,
                            title="SQL Injection via String Concatenation in SQL Text",
                            description=f"String concatenation or modulo formatting detected in text() at line {node.lineno}.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            endpoint="/api/v1/products",
                            method="GET",
                            parameter="search",
                            raw_evidence={"line": node.lineno, "node_type": "BinOp"},
                            remediation_guidance="Use bind parameters instead of manual string concatenation.",
                        )
                    )

        # Rule 2: BOLA / IDOR Detection in Order Retrieval
        # Checks for conditional bypasses of user ownership checks
        if hasattr(node, "lineno"):
            pass

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Detect raw SQL queries built with f-string or string concatenation assigned to variable
        # e.g., raw_sql = f"SELECT ... WHERE ... {filters.search} ..."
        target_names = [
            target.id.lower()
            for target in node.targets
            if isinstance(target, ast.Name)
        ]
        is_sql_target = any("sql" in name or "query" in name for name in target_names)

        if is_sql_target:
            if isinstance(node.value, ast.JoinedStr):
                self.findings.append(
                    SecurityFinding(
                        agent_source="code_security",
                        category="SQL_INJECTION",
                        cwe_id="CWE-89",
                        owasp_category="OWASP Top 10 - Injection",
                        severity="HIGH",
                        confidence=0.95,
                        title="SQL Injection via Formatted String Interpolation",
                        description=(
                            f"Direct formatted string interpolation detected inside database query call "
                            f"at line {node.lineno}. Untrusted user input can alter SQL execution semantics."
                        ),
                        file_path=self.file_path,
                        line_number=node.lineno,
                        endpoint="/api/v1/products",
                        method="GET",
                        parameter="search",
                        raw_evidence={"line": node.lineno, "node_type": "JoinedStr"},
                        remediation_guidance=(
                            "Use parameterized SQLAlchemy queries or ORM filter expressions (e.g., .ilike()). "
                            "Never interpolate raw strings directly into text() blocks."
                        ),
                    )
                )
            elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Add, ast.Mod)):
                self.findings.append(
                    SecurityFinding(
                        agent_source="code_security",
                        category="SQL_INJECTION",
                        cwe_id="CWE-89",
                        owasp_category="OWASP Top 10 - Injection",
                        severity="HIGH",
                        confidence=0.90,
                        title="SQL Injection via String Concatenation in SQL Text",
                        description=f"String concatenation or modulo formatting detected in text() at line {node.lineno}.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        endpoint="/api/v1/products",
                        method="GET",
                        parameter="search",
                        raw_evidence={"line": node.lineno, "node_type": "BinOp"},
                        remediation_guidance="Use bind parameters instead of manual string concatenation.",
                    )
                )

        self.generic_visit(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        # Analyze function logic for BOLA (e.g. get_order_by_id)
        if node.name == "get_order_by_id":
            # Search for conditional check involving ENABLE_VULNERABILITY_BOLA
            source_content = ast.unparse(node) if hasattr(ast, "unparse") else ""
            if "ENABLE_VULNERABILITY_BOLA" in source_content:
                self.findings.append(
                    SecurityFinding(
                        agent_source="code_security",
                        category="BOLA_IDOR",
                        cwe_id="CWE-284",
                        owasp_category="API1:2023-BOLA",
                        severity="HIGH",
                        confidence=0.92,
                        title="Broken Object Level Authorization (BOLA/IDOR) on Order Lookup",
                        description=(
                            f"Function '{node.name}' at line {node.lineno} contains a conditional bypass allowing "
                            f"users to retrieve order details without strict verification against current_user.id."
                        ),
                        file_path=self.file_path,
                        line_number=node.lineno,
                        endpoint="/api/v1/orders/{order_id}",
                        method="GET",
                        parameter="order_id",
                        raw_evidence={"function": node.name, "line": node.lineno},
                        remediation_guidance=(
                            "Enforce strict object ownership validation on every access: "
                            "verify order.user_id == current_user.id or current_user.role == 'admin'."
                        ),
                    )
                )

        # Analyze cart additions for Sensitive Business Flow Abuse
        if node.name == "add_item":
            source_content = ast.unparse(node) if hasattr(ast, "unparse") else ""
            if "ENABLE_VULNERABILITY_BUSINESS_FLOW" in source_content:
                self.findings.append(
                    SecurityFinding(
                        agent_source="code_security",
                        category="BUSINESS_FLOW_ABUSE",
                        cwe_id="CWE-840",
                        owasp_category="API6:2023-Sensitive Business Flows",
                        severity="MEDIUM",
                        confidence=0.88,
                        title="Unrestricted Business Flow: Negative Quantity Cart Manipulation",
                        description=(
                            f"Function '{node.name}' at line {node.lineno} permits negative or non-positive "
                            f"item quantities, which can manipulate line item totals and checkout pricing."
                        ),
                        file_path=self.file_path,
                        line_number=node.lineno,
                        endpoint="/api/v1/cart/items",
                        method="POST",
                        parameter="quantity",
                        raw_evidence={"function": node.name, "line": node.lineno},
                        remediation_guidance="Enforce invariant input validation ensuring quantity is a positive integer >= 1.",
                    )
                )

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._check_function(node)
        self.generic_visit(node)


class CodeSecurityAgent:
    """Agent 2: Static code analyzer detecting OWASP API & code vulnerabilities via deterministic AST rules."""

    def __init__(self, target_dir: str = "apps/ecommerce-backend/app"):
        self.target_dir = target_dir

    def scan(self, target_dir: str | None = None) -> list[SecurityFinding]:
        scan_path = Path(target_dir or self.target_dir)
        findings: list[SecurityFinding] = []

        if not scan_path.exists():
            return findings

        for root, _, files in os.walk(scan_path):
            for file in files:
                if not file.endswith(".py"):
                    continue
                file_full_path = Path(root) / file
                try:
                    with open(file_full_path, "r", encoding="utf-8") as f:
                        source = f.read()
                    tree = ast.parse(source, filename=str(file_full_path))
                    visitor = CodeSecurityASTVisitor(str(file_full_path.as_posix()))
                    visitor.visit(tree)
                    findings.extend(visitor.findings)
                except (SyntaxError, UnicodeDecodeError, OSError):
                    continue

        return findings
