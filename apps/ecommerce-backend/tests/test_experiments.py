"""Comprehensive test suite for Phase 12: Quantitative Research Evaluation & Experiment Suite (RQ1-RQ4)."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient

from experiments.benchmarks.cybershield_comparator import CyberShieldComparator
from experiments.benchmarks.regex_waf_comparator import RegexWafComparator
from experiments.benchmarks.sync_llm_comparator import SyncLlmComparator
from experiments.benchmarks.vanilla_unprotected import VanillaUnprotectedComparator
from experiments.datasets.corpus_loader import CorpusLoader
from experiments.exporters.latex_table_exporter import LatexTableExporter
from experiments.exporters.markdown_report_exporter import MarkdownReportExporter
from experiments.exporters.metrics_summary import MetricsSummarizer
from experiments.suites.exp1_latency_overhead import LatencyOverheadExperiment
from experiments.suites.exp2_triangulation import TriangulationAccuracyExperiment
from experiments.suites.exp3_concurrency_nat import ConcurrencyNatExperiment
from experiments.suites.exp4_remediation import AutomatedRemediationExperiment


def test_corpus_loader_integrity():
    """Verify loading, category filtering, and reproducibility of the ground-truth dataset."""
    loader = CorpusLoader()
    corpus = loader.load_corpus()

    assert "metadata" in corpus
    assert "benign_queries" in corpus
    assert "attack_payloads" in corpus
    assert len(corpus["benign_queries"]) >= 100
    assert len(corpus["attack_payloads"]) >= 30

    # Test filtering
    sqli_attacks = loader.get_attack_payloads(category="SQLI")
    assert len(sqli_attacks) > 0
    assert all(a["category"] == "SQLI" for a in sqli_attacks)

    bola_attacks = loader.get_attack_payloads(category="BOLA")
    assert len(bola_attacks) > 0
    assert all(a["category"] == "BOLA" for a in bola_attacks)

    # Test batch sampling reproducibility
    batch_1 = loader.get_mixed_evaluation_batch(benign_count=20, attack_count=10, seed=123)
    batch_2 = loader.get_mixed_evaluation_batch(benign_count=20, attack_count=10, seed=123)
    assert len(batch_1) == 30
    assert batch_1 == batch_2


def test_defense_comparators():
    """Verify baseline behavior across Vanilla, Regex WAF, Sync LLM, and CyberShield."""
    benign_query = "Select classic leather jacket"
    attack_payload = "1' OR 1=1; DROP TABLE products; --"

    vanilla = VanillaUnprotectedComparator()
    waf = RegexWafComparator()
    llm = SyncLlmComparator()
    cs = CyberShieldComparator()

    # 1. Vanilla (passthrough)
    res_v_benign = vanilla.evaluate(benign_query, is_attack=False)
    assert not res_v_benign.blocked
    assert res_v_benign.is_true_negative
    res_v_atk = vanilla.evaluate(attack_payload, is_attack=True)
    assert not res_v_atk.blocked
    assert res_v_atk.is_false_negative

    # 2. Regex WAF (keyword false positive on 'Select')
    res_waf_benign = waf.evaluate(benign_query, is_attack=False)
    assert res_waf_benign.blocked  # Triggers false positive
    assert res_waf_benign.is_false_positive
    res_waf_atk = waf.evaluate(attack_payload, is_attack=True)
    assert res_waf_atk.blocked
    assert res_waf_atk.is_true_positive

    # 3. Sync LLM (accurate but severe latency penalty)
    res_llm_benign = llm.evaluate(benign_query, is_attack=False)
    assert not res_llm_benign.blocked
    assert res_llm_benign.latency_ms > 500.0  # Emulates LLM API overhead

    # 4. CyberShield (sub-2ms fast-path & 0% FPR)
    res_cs_benign = cs.evaluate(benign_query, is_attack=False)
    assert not res_cs_benign.blocked
    assert res_cs_benign.is_true_negative
    assert res_cs_benign.latency_ms <= 2.5
    res_cs_atk = cs.evaluate(attack_payload, is_attack=True)
    assert res_cs_atk.blocked
    assert res_cs_atk.is_true_positive


def test_rq1_latency_overhead_suite():
    """Verify RQ1 micro-benchmark latency calculations and sub-2ms assertion."""
    exp1 = LatencyOverheadExperiment()
    results = exp1.run(sample_size=30, seed=42)

    assert results["experiment_id"] == "EXP-1-LATENCY"
    comps = results["comparators"]
    assert "CyberShield Dual-Plane" in comps
    assert "Synchronous LLM-in-the-Loop" in comps
    assert "Vanilla Unprotected" in comps

    cs_stats = comps["CyberShield Dual-Plane"]
    assert cs_stats["p99_ms"] <= 2.5
    assert cs_stats["sub_2ms_compliance"] is True

    llm_stats = comps["Synchronous LLM-in-the-Loop"]
    assert llm_stats["p99_ms"] > 500.0
    assert llm_stats["sub_2ms_compliance"] is False


def test_rq2_triangulation_accuracy_suite():
    """Verify RQ2 Bayesian triangulation accuracy, composite escalation, and zero FPR."""
    exp2 = TriangulationAccuracyExperiment()
    results = exp2.run(sample_size=30, seed=42)

    assert results["experiment_id"] == "EXP-2-TRIANGULATION"
    cs_acc = results["cybershield_triangulated"]
    assert cs_acc["fpr"] == 0.0
    assert cs_acc["tpr"] == 100.0
    assert cs_acc["precision"] == 100.0

    waf_acc = results["signature_waf"]
    assert waf_acc["false_positives_count"] > 0
    assert waf_acc["fpr"] > 0.0

    tiers = results["bayesian_escalation_curve"]
    assert tiers["3_Pillars_Triangulated"]["composite"] >= 0.99
    assert tiers["3_Pillars_Triangulated"]["fpr_estimate"] == 0.0


def test_rq3_concurrency_nat_suite():
    """Verify RQ3 multi-tenant NAT disambiguation under traffic storm."""
    exp3 = ConcurrencyNatExperiment()
    results = exp3.run(shopper_count=20, attacker_count=10, reqs_per_shopper=3, reqs_per_attacker=3)

    assert results["experiment_id"] == "EXP-3-CONCURRENCY-NAT"
    naive = results["naive_ip_waf"]
    cs = results["cybershield"]

    # CyberShield maintains all legitimate shoppers
    assert cs["lspr_percentage"] >= 99.5
    assert cs["acr_percentage"] >= 99.0
    assert cs["fpr_percentage"] == 0.0
    assert cs["zero_fp_achieved"] is True

    # Naive IP WAF triggers IP block and collateral damage
    assert naive["ip_block_triggered"] is True
    assert naive["fpr_percentage"] > 0.0
    assert naive["lspr_percentage"] < 50.0


def test_rq4_automated_remediation_suite():
    """Verify RQ4 AST patch synthesis, sandbox validation, and zero functional regressions."""
    exp4 = AutomatedRemediationExperiment()
    results = exp4.run(iterations_per_target=2)

    assert results["experiment_id"] == "EXP-4-REMEDIATION"
    metrics = results["metrics"]
    assert metrics["syntax_validity_rate"] == 100.0
    assert metrics["exploit_neutralization_rate"] == 100.0
    assert metrics["regression_rate"] == 0.0
    assert metrics["zero_regression_achieved"] is True
    assert metrics["full_neutralization_achieved"] is True
    assert metrics["mean_end_to_end_cycle_ms"] < 100.0  # < 100ms fast remediation

    evals = results["evaluations"]
    assert len(evals) == 4
    cwes = {e["cwe_id"] for e in evals}
    assert cwes == {"CWE-89", "CWE-284", "CWE-840", "CWE-798"}


def test_metrics_summarizer_and_exporters(tmp_path: Path):
    """Verify statistical distributions, LaTeX table export, and Markdown report rendering."""
    # Distribution calculation
    latencies = [1.2, 1.3, 1.25, 1.4, 1.15, 1.22, 1.35]
    dist = MetricsSummarizer.compute_distribution(latencies)
    assert dist["count"] == 7
    assert dist["p50"] > 1.0
    assert dist["ci_lower"] <= dist["mean"] <= dist["ci_upper"]

    # Run quick benchmark results for export verification
    exp1 = LatencyOverheadExperiment().run(sample_size=20, seed=42)
    exp2 = TriangulationAccuracyExperiment().run(sample_size=20, seed=42)
    exp3 = ConcurrencyNatExperiment().run(shopper_count=10, attacker_count=5, reqs_per_shopper=2, reqs_per_attacker=2)
    exp4 = AutomatedRemediationExperiment().run(iterations_per_target=1)

    # Synthesis
    synthesis = MetricsSummarizer.synthesize_all(exp1, exp2, exp3, exp4)
    assert synthesis["research_questions"]["RQ1_Latency_Overhead"]["status"] == "VALIDATED"
    assert synthesis["research_questions"]["RQ2_Triangulation_Accuracy"]["status"] == "VALIDATED"
    assert synthesis["research_questions"]["RQ3_Session_Preservation_NAT"]["status"] == "VALIDATED"
    assert synthesis["research_questions"]["RQ4_Automated_Remediation"]["status"] == "VALIDATED"

    # LaTeX export
    tex_files = LatexTableExporter.export_all(exp1, exp2, exp3, exp4, tmp_path)
    assert len(tex_files) == 4
    for fpath in tex_files.values():
        assert fpath.is_file()
        content = fpath.read_text(encoding="utf-8")
        assert "\\begin{table}" in content
        assert "\\begin{tabular}" in content
        assert "\\bottomrule" in content

    # Markdown report export
    md_file = tmp_path / "report.md"
    MarkdownReportExporter.export_report(exp1, exp2, exp3, exp4, md_file)
    assert md_file.is_file()
    md_content = md_file.read_text(encoding="utf-8")
    assert "# CyberShield Empirical Research Evaluation Report" in md_content
    assert "RQ1: Fast-Path Latency & Throughput Scalability" in md_content
    assert "RQ2: Bayesian Triangulation & False Positive Elimination" in md_content
    assert "RQ3: Concurrency & Shared-IP NAT Session Preservation" in md_content
    assert "RQ4: Automated AST Remediation & Non-Regression Validation" in md_content


@pytest.mark.asyncio
async def test_experiments_rest_api_lifecycle(async_client: AsyncClient):
    """Test REST API endpoints for triggering and retrieving evaluation benchmark metrics."""
    # 1. Trigger benchmark trial via REST
    run_payload = {
        "run_exp1": True,
        "run_exp2": True,
        "run_exp3": True,
        "run_exp4": True,
        "sample_size": 20,
        "export_latex": True,
        "export_markdown": True,
    }
    run_res = await async_client.post("/security/v1/experiments/run", json=run_payload)
    assert run_res.status_code == 200
    data = run_res.json()
    assert "research_questions" in data
    assert data["research_questions"]["RQ1_Latency_Overhead"]["status"] == "VALIDATED"

    # 2. Get latest results
    results_res = await async_client.get("/security/v1/experiments/results")
    assert results_res.status_code == 200
    cached_data = results_res.json()
    assert "research_questions" in cached_data

    # 3. Retrieve LaTeX table endpoints
    latex_res = await async_client.get("/security/v1/experiments/results/rq1/latex")
    assert latex_res.status_code == 200
    assert "\\begin{table}" in latex_res.text

    latex_rq2_res = await async_client.get("/security/v1/experiments/results/rq2/latex")
    assert latex_rq2_res.status_code == 200
    assert "RQ2: Triangulation Detection Accuracy" in latex_rq2_res.text

    # Invalid RQ ID 404 check
    invalid_res = await async_client.get("/security/v1/experiments/results/rq99_unknown/latex")
    assert invalid_res.status_code == 404

    # 4. Retrieve Markdown report endpoint
    report_res = await async_client.get("/security/v1/experiments/report")
    assert report_res.status_code == 200
    assert "# CyberShield Empirical Research Evaluation Report" in report_res.text
