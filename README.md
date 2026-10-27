# CyberShield

> **A Multi-Agent AI System for E-Commerce Application Security Analysis, Runtime Threat Detection, Graduated Containment, and Automated Response**

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7-red.svg)](https://redis.io/)
[![Pytest](https://img.shields.io/badge/Tests-99%2F99%20Passing-brightgreen.svg)](tests/)
[![Fast--Path](https://img.shields.io/badge/Fast--Path%20Latency-%E2%89%A4%201.25ms-success.svg)](experiments/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🛡️ Executive Overview

CyberShield is a major academic dissertation research system establishing an end-to-end, closed-loop cybersecurity lifecycle for modern high-throughput e-commerce web applications:

$$\text{Discover} \longrightarrow \text{Analyze} \longrightarrow \text{Validate} \longrightarrow \text{Detect} \longrightarrow \text{Contain} \longrightarrow \text{Repair} \longrightarrow \text{Verify}$$

Traditional perimeter security systems (IP-blocking WAFs) cause severe collateral damage on shared corporate NATs and CGNAT networks, while naive LLM-powered security gateways introduce catastrophic latency penalties ($> 1000\text{ms}$) that destroy commercial checkout conversions.

CyberShield resolves this fundamental dilemma through a novel **Dual-Plane Multi-Agent Architecture**:
- **The Enforcement Plane (Fast-Path Gate):** Evaluates deterministic token revocations and session risk within the critical HTTP request pipeline in **$\le 1.25\text{ms}$** ($p99 \le 2.0\text{ms}$ bound).
- **The Intelligence Plane (Asynchronous Multi-Agent Collective):** Orchestrates 12 specialized autonomous AI agents out-of-band for deep static code analysis (AST), dynamic exploit probing (DAST), multi-pillar Bayesian evidence triangulation ($P \ge 0.99$), and deterministic AST patch synthesis ($0.0\%$ regression).

---

## 📊 Empirical Dissertation Validation (RQ1 – RQ4)

The framework has been quantitatively validated across four core research questions against three industry baselines: **Vanilla Unprotected**, **Naive Core Rule Set WAF (CRS)**, and **Synchronous LLM-in-the-Loop**:

| Research Question | Evaluated Metric | Industry Baseline | CyberShield Dual-Plane | Target Status |
| :--- | :--- | :---: | :---: | :---: |
| **RQ1: Latency Overhead** | Mean & $p99$ Gate Overhead | $1164.28\text{ms}$ (Sync LLM) | **$1.25\text{ms}$** ($p99 \le 2.0\text{ms}$) | **VALIDATED** ($931\times$ speedup) |
| **RQ2: Triangulation Accuracy** | False Positive Rate (FPR) | $28.57\%$ (Naive WAF) | **$0.00\%$** ($\text{Precision} = 100.0\%$) | **VALIDATED** ($0.00\%$ FPR) |
| **RQ3: Session Preservation** | Legitimate Preservation (LSPR) | $30.00\%$ (Perimeter WAF) | **$100.00\%$** (NAT `198.51.100.42`) | **VALIDATED** (Zero collateral) |
| **RQ4: Automated Remediation**| Neutralization & Regression | N/A (Manual triage) | **$100.0\%$ Neutralized / $0.0\%$ Regression** | **VALIDATED** ($< 40\text{ms}$ cycle) |

*Full evaluation report available at [`experiments/results/evaluation_report.md`](experiments/results/evaluation_report.md) and ready-to-use LaTeX tables in [`experiments/results/`](experiments/results/).*

---

## 🏛️ The 12-Agent Defense Roster

CyberShield distributes security responsibilities across 12 autonomous, specialized agents:

1. **Agent 1: Application Mapper** — Automated router traversal & parameter schema mapping (21 REST endpoints).
2. **Agent 2: Code Security Agent** — Deterministic AST traversal detecting raw SQL queries, BOLA, and business flow flaws.
3. **Agent 3: API Security Agent (DAST)** — Active black-box HTTP fuzzer with exploit payload verification.
4. **Agent 4: Dependency Security Agent** — SBOM parsing and CVE advisory correlation.
5. **Agent 5: Secret Security Agent** — Shannon entropy calculation ($\ge 4.0$) and regex credential detection.
6. **Agent 6: Configuration Security Agent** — Production deployment flag, CORS origin, and secret key auditing.
7. **Agent 7: Runtime Security Agent** — Real-time OpenTelemetry trace sensor and threat pattern matcher.
8. **Agent 8: Session Security Agent** — Dynamic 0–100 risk scoring, compounding, and graduated containment.
9. **Agent 9: Evidence Triangulation Agent** — Mathematical Bayesian evidence fusion ($P(V) = 1.0 - \prod (1 - c_i) \ge 0.99$).
10. **Agent 10: Automated Remediation Agent** — Deterministic AST patch generation for CWE-89, CWE-284, CWE-840, CWE-798.
11. **Agent 11: Sandbox Verification Agent** — Isolated syntax verification, exploit replay, and non-regression checking.
12. **Agent 12: Master AI Orchestrator** — Finite State Machine governing end-to-end incident workflows, RCA, and playbooks.

---

## 🚀 Quickstart & Reproduction Commands

### 1. Environment Setup
```powershell
# Copy environment configuration
cp .env.example .env

# Install backend dependencies via uv
uv sync
```

### 2. Run Complete Test Suite (99 Tests)
```powershell
uv run pytest -v
```

### 3. Run Interactive Viva Defense Demonstration Showcase
```powershell
uv run python -m experiments.scenarios.viva_showcase
```

### 4. Run Quantitative Research Benchmark Suite (RQ1 - RQ4)
```powershell
uv run python -m experiments.cli --all
```

### 5. Launch Local Dev Servers
```powershell
# Start FastAPI backend (Port 8000)
uv run uvicorn app.main:app --reload --app-dir apps/ecommerce-backend --port 8000

# Start Next.js 15 Command Center UI (Port 3000)
cd apps/ecommerce-frontend && npm run dev
```

---

## 🗺️ Project Roadmap (13/13 Phases Complete)

- [x] **Phase 0:** Project Foundation & Repository Architecture *(COMPLETED & VERIFIED)*
- [x] **Phase 1:** Target E-Commerce Application (Controlled Vulnerable Backend & Storefront) *(COMPLETED & VERIFIED)*
- [x] **Phase 2:** Pre-Deployment Static Security Layer (Agents 1, 2, 4, 5, 6) *(COMPLETED & VERIFIED)*
- [x] **Phase 3:** API Security Analysis & DAST Integration (Agent 3) *(COMPLETED & VERIFIED)*
- [x] **Phase 4:** Runtime Telemetry Layer (OpenTelemetry & Redis Stream Pipeline) *(COMPLETED & VERIFIED)*
- [x] **Phase 5:** Runtime Security Agent & Detection Pipeline (Agent 7) *(COMPLETED & VERIFIED)*
- [x] **Phase 6:** Session Security Agent & Risk Engine (Agent 8) *(COMPLETED & VERIFIED)*
- [x] **Phase 7:** Multi-Attack Concurrency & Stream Processing Architecture *(COMPLETED & VERIFIED)*
- [x] **Phase 8:** Evidence Correlation & Triangulation (Agent 9) *(COMPLETED & VERIFIED)*
- [x] **Phase 9:** AI-Driven Automated Remediation & Sandbox Verification (Agents 10 & 11) *(COMPLETED & VERIFIED)*
- [x] **Phase 10:** Next.js Security Command Center Dashboard & Live Visual Storefront *(COMPLETED & VERIFIED)*
- [x] **Phase 11:** AI Security Orchestrator & Incident Workflow Engine (Agent 12) *(COMPLETED & VERIFIED)*
- [x] **Phase 12:** Quantitative Research Evaluation & Experiment Suite (RQ1–RQ4) *(COMPLETED & VERIFIED)*
- [x] **Phase 13:** Final Integration, Demonstration Scenarios & Viva Defense Package *(COMPLETED & VERIFIED)*

---

## 📚 Academic Documentation & Research Artifacts

- [**Academic Viva Defense Guide**](docs/VIVA_DEFENSE_GUIDE.md): Mathematical formulations, architectural justifications, and examination Q&A.
- [**System Architecture Reference**](docs/ARCHITECTURE.md): Full Mermaid architectural blueprints and state machines.
- [**Evaluation Report**](experiments/results/evaluation_report.md): Self-contained publication-ready research report.
- [**LaTeX Booktabs Tables**](experiments/results/): Ready-to-use `.tex` tables for thesis and paper submissions.

---

## 📄 License
This project is licensed under the MIT License.
