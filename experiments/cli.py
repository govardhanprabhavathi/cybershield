"""Command-line runner for CyberShield quantitative research experiments."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from experiments.exporters.latex_table_exporter import LatexTableExporter
from experiments.exporters.markdown_report_exporter import MarkdownReportExporter
from experiments.exporters.metrics_summary import MetricsSummarizer
from experiments.suites.exp1_latency_overhead import LatencyOverheadExperiment
from experiments.suites.exp2_triangulation import TriangulationAccuracyExperiment
from experiments.suites.exp3_concurrency_nat import ConcurrencyNatExperiment
from experiments.suites.exp4_remediation import AutomatedRemediationExperiment


def run_experiment_suite(
    run_exp1: bool = True,
    run_exp2: bool = True,
    run_exp3: bool = True,
    run_exp4: bool = True,
    sample_size: int = 100,
    output_dir: Path | str = "experiments/results",
    export_latex: bool = True,
    export_markdown: bool = True,
) -> dict[str, Any]:
    """Execute requested benchmarks, persist JSON outputs, and optionally generate LaTeX & Markdown."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {}

    print("=" * 70)
    print(" CyberShield Quantitative Research Benchmark Runner (RQ1 - RQ4)")
    print("=" * 70)

    # RQ1: Latency Overhead
    if run_exp1:
        print("\n[+] Running Experiment 1: RQ1 Runtime Latency Overhead...")
        exp1 = LatencyOverheadExperiment()
        res1 = exp1.run(sample_size=sample_size)
        results["exp1"] = res1
        (out_path / "rq1_latency_overhead.json").write_text(json.dumps(res1, indent=2), encoding="utf-8")
        comps = res1.get("comparators", {})
        cs = comps.get("CyberShield Dual-Plane", {})
        print(f"    CyberShield Fast-Path Latency: mean={cs.get('mean_ms')}ms, p99={cs.get('p99_ms')}ms (sub-2ms: {cs.get('sub_2ms_compliance')})")

    # RQ2: Triangulation Accuracy
    if run_exp2:
        print("\n[+] Running Experiment 2: RQ2 Bayesian Evidence Triangulation...")
        exp2 = TriangulationAccuracyExperiment()
        res2 = exp2.run(sample_size=sample_size)
        results["exp2"] = res2
        (out_path / "rq2_triangulation_accuracy.json").write_text(json.dumps(res2, indent=2), encoding="utf-8")
        cs_acc = res2.get("cybershield_triangulated", {})
        print(f"    CyberShield Accuracy: TPR={cs_acc.get('tpr')}%, FPR={cs_acc.get('fpr')}%, Precision={cs_acc.get('precision')}%")

    # RQ3: Concurrency & Shared-IP NAT
    if run_exp3:
        print("\n[+] Running Experiment 3: RQ3 Multi-Tenant & NAT Session Preservation...")
        exp3 = ConcurrencyNatExperiment()
        res3 = exp3.run(shopper_count=50, attacker_count=25, reqs_per_shopper=4, reqs_per_attacker=4)
        results["exp3"] = res3
        (out_path / "rq3_concurrency_nat.json").write_text(json.dumps(res3, indent=2), encoding="utf-8")
        cs_nat = res3.get("cybershield", {})
        print(f"    CyberShield NAT Storm: LSPR={cs_nat.get('lspr_percentage')}%, ACR={cs_nat.get('acr_percentage')}%, FPR={cs_nat.get('fpr_percentage')}%")

    # RQ4: Automated Remediation
    if run_exp4:
        print("\n[+] Running Experiment 4: RQ4 Automated Remediation & Zero Regressions...")
        exp4 = AutomatedRemediationExperiment()
        res4 = exp4.run(iterations_per_target=3)
        results["exp4"] = res4
        (out_path / "rq4_remediation.json").write_text(json.dumps(res4, indent=2), encoding="utf-8")
        rem = res4.get("metrics", {})
        print(f"    CyberShield AST Patcher: Syntax={rem.get('syntax_validity_rate')}%, Neutralized={rem.get('exploit_neutralization_rate')}%, Regression={rem.get('regression_rate')}%")

    # Synthesis
    if all(k in results for k in ["exp1", "exp2", "exp3", "exp4"]):
        synthesis = MetricsSummarizer.synthesize_all(
            results["exp1"], results["exp2"], results["exp3"], results["exp4"]
        )
        (out_path / "evaluation_summary.json").write_text(json.dumps(synthesis, indent=2), encoding="utf-8")

        if export_latex:
            print("\n[+] Exporting LaTeX booktabs tables...")
            latex_files = LatexTableExporter.export_all(
                results["exp1"], results["exp2"], results["exp3"], results["exp4"], out_path
            )
            for fname in latex_files:
                print(f"    Exported {fname}")

        if export_markdown:
            print("\n[+] Exporting comprehensive Markdown evaluation report...")
            rep_path = MarkdownReportExporter.export_report(
                results["exp1"], results["exp2"], results["exp3"], results["exp4"], out_path / "evaluation_report.md"
            )
            print(f"    Exported {rep_path.name}")

    print("\n" + "=" * 70)
    print(" Benchmark execution completed successfully. Artifacts saved to:", out_path.resolve())
    print("=" * 70)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberShield Quantitative Research Evaluation Suite")
    parser.add_argument("--all", action="store_true", default=True, help="Run all 4 research experiment suites")
    parser.add_argument("--exp1", action="store_true", help="Run RQ1 Latency Overhead experiment")
    parser.add_argument("--exp2", action="store_true", help="Run RQ2 Bayesian Triangulation experiment")
    parser.add_argument("--exp3", action="store_true", help="Run RQ3 Concurrency NAT experiment")
    parser.add_argument("--exp4", action="store_true", help="Run RQ4 Automated Remediation experiment")
    parser.add_argument("--sample-size", type=int, default=100, help="Payload batch sample size")
    parser.add_argument("--output-dir", type=str, default="experiments/results", help="Destination results directory")
    parser.add_argument("--no-latex", action="store_true", help="Disable LaTeX export")
    parser.add_argument("--no-md", action="store_true", help="Disable Markdown report export")

    args = parser.parse_args()

    explicit_any = any([args.exp1, args.exp2, args.exp3, args.exp4])
    r1 = args.exp1 if explicit_any else True
    r2 = args.exp2 if explicit_any else True
    r3 = args.exp3 if explicit_any else True
    r4 = args.exp4 if explicit_any else True

    run_experiment_suite(
        run_exp1=r1,
        run_exp2=r2,
        run_exp3=r3,
        run_exp4=r4,
        sample_size=args.sample_size,
        output_dir=args.output_dir,
        export_latex=not args.no_latex,
        export_markdown=not args.no_md,
    )


if __name__ == "__main__":
    main()
