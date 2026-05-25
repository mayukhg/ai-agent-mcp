# Stakeholder Briefing: Agent Val MCP Server
## Extending Qualys ETM Capabilities to the AI-Agent Interface

---

## 1. Executive Summary: The Agentic Future of IT Operations

Enterprise AI agents are rapidly becoming the primary interface through which modern organizations execute operational workflows across DevOps, IT operations, and cybersecurity. As this shift accelerates, software products that expose their capabilities to these conversational AI interfaces will capture the next wave of enterprise consumption. Those that do not will become invisible.

The **Agent Val MCP (Model Context Protocol) Server** bridges this gap. By wrapping the core orchestration and execution logic of the **Qualys ETM (Enterprise Threat Management)** platform inside a standard, secure MCP interface, we enable corporate AI assistants (such as Microsoft Copilot Studio, Google Gemini, Anthropic Claude, and custom corporate Slack/Teams bots) to discover, validate, and remediate critical security vulnerabilities using natural language.

---

## 2. Stakeholder Value Propositions

### 🛡️ For the CISO & Security Operations Leaders
* **Shrinking MTTR from Weeks to Minutes**: Traditional vulnerability handovers are plagued by communication bottlenecks (tickets, asset ownership searches). The MCP Server closes the loop directly in collaboration spaces (Slack/Teams).
* **Immutable Policy Governance**: Security policies are exposed as read-only system configurations (`config://governance/autonomy-matrix`). The external AI agent is programmatically blocked from executing actions outside pre-approved maintenance windows or on critical assets without explicit manager sign-off.
* **Audit-Ready Actions**: Every patch or mitigation script executed by the agent requires and records a corporate change-control ticket ID, creating a seamless, compliant trail.

### ⚙️ For DevOps & Product Engineering Leaders
* **Zero Friction AppSec**: Decentralized project teams do not log into standalone security dashboards. The MCP server brings vulnerability discovery and remediation directly to their existing developer tools (Slack, Teams, and Command Line Interfaces).
* **Safe Validation with TruConfirm**: Developers can safely verify whether an exploit path is actively viable using safe, non-destructive cryptographic checks (`delegate_validation_workflow`), avoiding false-positive disputes.
* **Near-Zero Footprint Remediation**: Remediations are executed via the lightweight Qualys Cloud Agent, operating with less than 5MB of runtime memory and virtually zero idle CPU overhead, guaranteeing application uptime and SLA stability.

### 💼 For Business Executives & Sales Directors
* **Driving Core Platform Licensing**: The MCP server is a frictionless gateway that drives massive downstream Qualys consumption. Every validation check invokes a **TruConfirm** subscription, and every remediation executes via a paid **Qualys Cloud Agent** license and a **TruRisk Eliminate** seat.
* **Tapping the Decentralized Developer Budget**: AppSec and DevOps budgets are merging. Exposing Qualys ETM as a collaborative AI capability allows Qualys to monetize the millions of developers who own security execution but never purchase traditional SOC dashboard tools.

---

## 3. The End-to-End Operational Lifecycle

The diagram below illustrates how the Agent Val MCP Server coordinates the security lifecycle within an everyday team chat room, eliminating human latency at each step.

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Product Engineer / DevOps
    actor Mgr as Engineering Manager (Approver)
    participant AI as Corporate AI Assistant
    participant MCP as Agent Val MCP Server
    participant ETM as Qualys ETM Platform APIs

    Dev->>AI: "We have an alert for CVE-2024-4577. Can we safely ignore it?"
    AI->>MCP: delegate_validation_workflow(asset="app-server-01", cve="CVE-2024-4577")
    MCP->>ETM: Invoke TruConfirm APIs (Safe execution check)
    ETM-->>MCP: Exploit verified viable (Cryptographic evidence)
    MCP-->>AI: Return validation proof & severity metrics
    AI->>AI: Format Pre-flight Blast Radius assessment card
    AI->>Mgr: Display interactive chat card: "Approve Patch & Re-validate?"
    Mgr->>AI: Clicks "Approve Mitigation" (Change Ticket ID #CC-5529)
    AI->>MCP: orchestrate_remediation(asset="app-server-01", action="patch", ticket="CC-5529")
    MCP->>ETM: Trigger TruRisk Eliminate via Qualys Cloud Agent
    ETM-->>MCP: Patch applied successfully (low footprint, <5MB RAM used)
    MCP-->>AI: Return success report & updated TruRisk Score (88 -> 30)
    AI->>Dev: "Exploit path closed. TruRisk reduced by 65%. Ticket #CC-5529 updated and closed."
```

---

## 4. Strategic Implementation Roadmap

```mermaid
gantt
    title Strategic Implementation Timeline
    dateFormat  YYYY-MM-DD
    section Horizon 1: MVP
    Read-Only FastMCP Server :active, h1_start, 2026-05-25, 30d
    Stateful Registry Simulation :active, h1_db, after h1_start, 20d
    section Horizon 2: Remediation
    TruRisk Eliminate API Hooks : h2_start, after h1_db, 45d
    Audit Token & Ticket Integrations : h2_audit, after h2_start, 30d
    section Horizon 3: Autonomy
    Dynamic Policy Enforcer Matrix : h3_start, after h2_audit, 60d
```

### 1️⃣ Horizon 1: The Minimum Viable Orchestrator (Months 1–3)
* **Goal**: Validate market demand and pipeline with zero backend changes.
* **Scope**: Build the read-only MCP server wrapper using FastMCP, exposing risk telemetry (`telemetry://active-session-logs/{asset_id}`), governance matrix resource (`config://`), and safe TruConfirm exploit checking tools (`delegate_validation_workflow`).
* **Effort**: Low risk, under 100 lines of standard Python, executing in regular feature sprints.

### 2️⃣ Horizon 2: Full Remediation Integration (Months 3–6)
* **Goal**: Enable safe, active remediation within the conversational workspace.
* **Scope**: Implement target tools for `orchestrate_remediation`, binding actions to active Qualys Cloud Agent footprints (Patch Management, Mitigate, and Network Isolation).

### 3️⃣ Horizon 3: Advanced Autonomy & Global Policy Sync (Months 6+)
* **Goal**: Run automated, hands-off patch pipelines.
* **Scope**: Integrate dynamic param filtering, enforcing strict governance boundaries and automated ticketing closures through native ETM synchronization.
