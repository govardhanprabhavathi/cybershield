"""Automated integration tests for Phase 13: Viva Defense Demonstration Showcase."""

from __future__ import annotations

from experiments.scenarios.viva_showcase import VivaShowcaseRunner


def test_viva_showcase_acts_individual_execution():
    """Verify that each Act of the Viva Defense scenario executes and satisfies research criteria."""
    runner = VivaShowcaseRunner(automated=True, pause_between_acts=False, delay_sec=0.0)

    # Act I
    res1 = runner.run_act_1_pre_deployment()
    assert res1["act"] == "ACT_I"
    assert res1["findings_count"] >= 3
    assert "CWE-89" in res1["vulnerabilities"]
    assert "CWE-284" in res1["vulnerabilities"]

    # Act II
    res2 = runner.run_act_2_adversary_exploit()
    assert res2["act"] == "ACT_II"
    assert res2["attacker_session"] == "sess_attacker_77"
    assert res2["egress_ip"] == "198.51.100.42"

    # Act III
    res3 = runner.run_act_3_runtime_detection_and_containment()
    assert res3["act"] == "ACT_III"
    assert res3["risk_score"] >= 90
    assert res3["confidence"] >= 0.85
    assert res3["response_state"] == "CONTAIN"
    assert res3["latency_ms"] <= 2.5  # Sub-2ms fast-path bound
    assert res3["attacker_blocked"] is True

    # Act IV
    res4 = runner.run_act_4_nat_disambiguation()
    assert res4["act"] == "ACT_IV"
    assert res4["lspr_percentage"] == 100.0
    assert res4["fpr_percentage"] == 0.0
    assert res4["alice_preserved"] is True

    # Act V
    res5 = runner.run_act_5_bayesian_triangulation()
    assert res5["act"] == "ACT_V"
    assert res5["composite_confidence"] >= 0.99
    assert res5["tier"] == "FULL_TRIANGULATION"
    assert res5["status"] == "ACTIVELY_EXPLOITED"

    # Act VI
    res6 = runner.run_act_6_autonomous_remediation()
    assert res6["act"] == "ACT_VI"
    assert res6["passed"] is True
    assert res6["strategy"] == "PARAMETERIZATION"
    assert res6["regression_rate"] == 0.0
    assert res6["cycle_ms"] < 100.0


def test_viva_showcase_end_to_end_suite():
    """Verify end-to-end execution of the complete 6-act demonstration sequence."""
    runner = VivaShowcaseRunner(automated=True, pause_between_acts=False, delay_sec=0.0)
    results = runner.execute_all()

    assert "act_1" in results
    assert "act_2" in results
    assert "act_3" in results
    assert "act_4" in results
    assert "act_5" in results
    assert "act_6" in results

    # Assert formal research criteria
    assert results["act_3"]["response_state"] == "CONTAIN"
    assert results["act_4"]["lspr_percentage"] == 100.0
    assert results["act_4"]["fpr_percentage"] == 0.0
    assert results["act_5"]["composite_confidence"] >= 0.99
    assert results["act_6"]["regression_rate"] == 0.0
