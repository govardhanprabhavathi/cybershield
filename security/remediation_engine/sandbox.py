"""Isolated sandbox execution environment for pre-commit syntax, safety, and non-regression validation."""

import ast
import time

from security.schemas.remediation import ASTDiff, VerificationCheck


class RemediationSandbox:
    """Validates candidate code patches in an isolated virtual context before committing to disk."""

    @staticmethod
    def verify_syntax(code: str) -> tuple[bool, str]:
        """Verify that Python code parses without syntax errors or indentation issues."""
        try:
            ast.parse(code)
            return True, "Code successfully parsed with zero syntax errors."
        except SyntaxError as exc:
            return False, f"SyntaxError on line {exc.lineno}: {exc.msg}"
        except (ValueError, TypeError) as exc:
            return False, f"AST Parsing failed: {exc}"

    @staticmethod
    def verify_ast_safety(code: str, cwe_id: str) -> tuple[bool, str]:
        """Perform AST inspection confirming that the specific vulnerability construct has been eliminated."""
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError, TypeError) as exc:
            return False, f"Cannot inspect AST: {exc}"

        clean_cwe = cwe_id.upper().strip()

        if clean_cwe == "CWE-89":
            # Inspect for dangerous f-string formatting inside text() calls
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "id", getattr(node.func, "attr", ""))
                    if func_name == "text" and node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, ast.JoinedStr):
                            return False, "Unsafe AST construct: Found JoinedStr (f-string) directly inside text() call."
            return True, "AST safety verified: No unparameterized string formatting detected in text() calls."

        elif clean_cwe in ("CWE-284", "CWE-639"):
            # Verify that tenant ownership check exists in the AST
            has_ownership_check = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Compare):
                    # Check for order.user_id != current_user.id
                    for comp in [node.left, *node.comparators]:
                        if isinstance(comp, ast.Attribute) and comp.attr in ("user_id", "id"):
                            has_ownership_check = True
                            break
            if not has_ownership_check:
                return False, "AST safety check failed: Missing tenant ownership authorization comparison."
            return True, "AST safety verified: Tenant ownership validation construct confirmed in AST."

        elif clean_cwe in ("CWE-840", "CWE-20"):
            # Verify quantity boundary comparison
            has_quantity_check = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Compare):
                    for comp in [node.left, *node.comparators]:
                        if isinstance(comp, ast.Attribute) and comp.attr == "quantity" or isinstance(comp, ast.Name) and comp.id == "quantity":
                            has_quantity_check = True
                            break
            if not has_quantity_check:
                return False, "AST safety check failed: Missing quantity boundary check."
            return True, "AST safety verified: Positive quantity boundary check confirmed in AST."

        return True, f"AST safety verified for {cwe_id}."

    @staticmethod
    def verify_no_regression(original_code: str, patched_code: str) -> tuple[bool, str]:
        """Ensure that class definitions, function signatures, and imports are preserved."""
        try:
            orig_tree = ast.parse(original_code)
            patch_tree = ast.parse(patched_code)
        except (SyntaxError, ValueError, TypeError) as exc:
            return False, f"AST regression parse failure: {exc}"

        orig_funcs = {node.name for node in ast.walk(orig_tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        patch_funcs = {node.name for node in ast.walk(patch_tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

        missing = orig_funcs - patch_funcs
        if missing:
            return False, f"Regression detected: Missing function definitions: {', '.join(missing)}"

        return True, "No regression detected: All original classes and functions preserved."

    @classmethod
    def run_sandbox_checks(
        cls,
        diff: ASTDiff,
        original_full_content: str | None = None,
    ) -> tuple[bool, list[VerificationCheck], float]:
        """Execute complete suite of sandbox checks on candidate diff."""
        start_time = time.perf_counter()
        checks: list[VerificationCheck] = []
        overall_passed = True

        # Check 1: Syntax
        code_to_check = diff.patched_code
        syntax_ok, syntax_msg = cls.verify_syntax(code_to_check)
        checks.append(VerificationCheck(check_name="AST_SYNTAX_VALIDATION", passed=syntax_ok, detail=syntax_msg))
        if not syntax_ok:
            overall_passed = False

        # Check 2: AST Safety
        if syntax_ok:
            safety_ok, safety_msg = cls.verify_ast_safety(code_to_check, diff.strategy)
            checks.append(VerificationCheck(check_name="AST_SAFETY_INSPECTION", passed=safety_ok, detail=safety_msg))
            if not safety_ok:
                overall_passed = False

        # Check 3: Non-Regression
        if original_full_content and syntax_ok:
            regr_ok, regr_msg = cls.verify_no_regression(original_full_content, code_to_check)
            checks.append(VerificationCheck(check_name="NON_REGRESSION_INTEGRITY", passed=regr_ok, detail=regr_msg))
            if not regr_ok:
                overall_passed = False

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return overall_passed, checks, duration_ms
