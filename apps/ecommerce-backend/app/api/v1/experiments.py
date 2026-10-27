"""REST API endpoints for triggering and retrieving quantitative research benchmarks (RQ1-RQ4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field

from experiments.cli import run_experiment_suite
from experiments.exporters.metrics_summary import MetricsSummarizer

router = APIRouter(prefix="/experiments", tags=["Quantitative Research Evaluation"])

RESULTS_DIR = Path("experiments/results")


class RunExperimentRequest(BaseModel):
    """Configuration options for executing evaluation benchmark suites."""

    run_exp1: bool = Field(default=True, description="Execute RQ1 Latency micro-benchmark")
    run_exp2: bool = Field(default=True, description="Execute RQ2 Triangulation accuracy benchmark")
    run_exp3: bool = Field(default=True, description="Execute RQ3 Concurrency NAT storm benchmark")
    run_exp4: bool = Field(default=True, description="Execute RQ4 Automated remediation benchmark")
    sample_size: int = Field(default=50, ge=10, le=500, description="Payload sample batch size")
    export_latex: bool = Field(default=True, description="Generate publication LaTeX tables")
    export_markdown: bool = Field(default=True, description="Generate Markdown evaluation report")


@router.post("/run", status_code=status.HTTP_200_OK)
async def run_experiments(request: RunExperimentRequest | None = None) -> dict[str, Any]:
    """Execute quantitative research benchmark suites across RQ1-RQ4."""
    req = request or RunExperimentRequest()

    try:
        results = run_experiment_suite(
            run_exp1=req.run_exp1,
            run_exp2=req.run_exp2,
            run_exp3=req.run_exp3,
            run_exp4=req.run_exp4,
            sample_size=req.sample_size,
            output_dir=RESULTS_DIR,
            export_latex=req.export_latex,
            export_markdown=req.export_markdown,
        )

        synthesis_file = RESULTS_DIR / "evaluation_summary.json"
        if synthesis_file.is_file():
            return json.loads(synthesis_file.read_text(encoding="utf-8"))

        return {
            "status": "COMPLETED",
            "executed_suites": list(results.keys()),
            "results": results,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evaluation benchmark execution failed: {exc}",
        ) from exc


@router.get("/results", status_code=status.HTTP_200_OK)
async def get_latest_results() -> dict[str, Any]:
    """Retrieve the cached quantitative benchmark results and research question validations."""
    summary_path = RESULTS_DIR / "evaluation_summary.json"
    if not summary_path.is_file():
        # Run lightweight benchmark trial if no results cached yet
        results = run_experiment_suite(
            run_exp1=True,
            run_exp2=True,
            run_exp3=True,
            run_exp4=True,
            sample_size=30,
            output_dir=RESULTS_DIR,
        )
        return MetricsSummarizer.synthesize_all(
            results["exp1"], results["exp2"], results["exp3"], results["exp4"]
        )

    return json.loads(summary_path.read_text(encoding="utf-8"))


@router.get("/results/{rq_id}/latex", status_code=status.HTTP_200_OK)
async def get_latex_table(rq_id: str) -> Response:
    """Retrieve publication-ready LaTeX booktabs table for a specific research question."""
    clean_id = rq_id.lower().replace("-", "_")

    filename_map = {
        "rq1": "table_rq1_latency.tex",
        "rq1_latency": "table_rq1_latency.tex",
        "rq2": "table_rq2_accuracy.tex",
        "rq2_accuracy": "table_rq2_accuracy.tex",
        "rq3": "table_rq3_nat.tex",
        "rq3_nat": "table_rq3_nat.tex",
        "rq4": "table_rq4_remediation.tex",
        "rq4_remediation": "table_rq4_remediation.tex",
    }

    tex_filename = filename_map.get(clean_id)
    if not tex_filename:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown research question ID '{rq_id}'. Valid IDs: rq1, rq2, rq3, rq4",
        )

    tex_path = RESULTS_DIR / tex_filename
    if not tex_path.is_file():
        # Generate on the fly
        await get_latest_results()

    if not tex_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LaTeX table not found for {rq_id}",
        )

    content = tex_path.read_text(encoding="utf-8")
    return Response(content=content, media_type="text/plain; charset=utf-8")


@router.get("/report", status_code=status.HTTP_200_OK)
async def get_markdown_report() -> Response:
    """Retrieve full publication-ready Markdown research evaluation report."""
    report_path = RESULTS_DIR / "evaluation_report.md"
    if not report_path.is_file():
        await get_latest_results()

    if not report_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evaluation report not found.",
        )

    content = report_path.read_text(encoding="utf-8")
    return Response(content=content, media_type="text/markdown; charset=utf-8")
