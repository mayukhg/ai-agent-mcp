import os
import json
import random
import logging
from datetime import datetime
from typing import Dict, Any, List
from dotenv import load_dotenv
from fastmcp import FastMCP

# Load configuration environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("AgentValMCPServer")

# Initialize FastMCP Server
mcp = FastMCP("Agent Val MCP Server")

# ------------------------------------------------------------------------------
# Stateful In-Memory Asset & Vulnerability Registry (Mock Database)
# ------------------------------------------------------------------------------
MOCK_ASSET_REGISTRY: Dict[str, Dict[str, Any]] = {
    "app-server-01": {
        "asset_name": "app-server-01",
        "ip_address": "10.120.45.10",
        "environment": "Production",
        "trurisk_score": 88,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2024-4577",
                "severity": "Critical",
                "cve_score": 9.8,
                "status": "Active",  # Active, Validated, Remediated
                "validation_proof": "None",
                "remediation_status": "Pending",  # Pending, Running, Success
                "last_scan": "2026-05-24T12:00:00Z"
            },
            {
                "cve_id": "CVE-2023-38646",
                "severity": "High",
                "cve_score": 8.1,
                "status": "Active",
                "validation_proof": "None",
                "remediation_status": "Pending",
                "last_scan": "2026-05-24T12:00:00Z"
            }
        ]
    },
    "db-host-05": {
        "asset_name": "db-host-05",
        "ip_address": "10.120.45.15",
        "environment": "Production",
        "trurisk_score": 92,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2024-3094",
                "severity": "Critical",
                "cve_score": 10.0,
                "status": "Active",
                "validation_proof": "None",
                "remediation_status": "Pending",
                "last_scan": "2026-05-24T12:00:00Z"
            }
        ]
    },
    "dev-box-09": {
        "asset_name": "dev-box-09",
        "ip_address": "192.168.12.80",
        "environment": "Development",
        "trurisk_score": 45,
        "vulnerabilities": [
            {
                "cve_id": "CVE-2021-44228",
                "severity": "Critical",
                "cve_score": 10.0,
                "status": "Active",
                "validation_proof": "None",
                "remediation_status": "Pending",
                "last_scan": "2026-05-24T12:00:00Z"
            }
        ]
    }
}

def get_or_create_asset(asset_id: str) -> Dict[str, Any]:
    """Retrieves an existing asset or dynamically generates a new one to simulate live lookup."""
    if asset_id in MOCK_ASSET_REGISTRY:
        return MOCK_ASSET_REGISTRY[asset_id]

    logger.info(f"Asset '{asset_id}' not found in registry. Generating dynamic asset telemetry.")
    ip_subnet = random.randint(10, 254)
    ip_host = random.randint(2, 254)
    env = "Development" if "dev" in asset_id.lower() or "test" in asset_id.lower() else "Production"
    
    # Generate a realistic random CVE vulnerability
    cve_year = random.randint(2023, 2025)
    cve_num = random.randint(1000, 9999)
    cve_id = f"CVE-{cve_year}-{cve_num}"
    
    MOCK_ASSET_REGISTRY[asset_id] = {
        "asset_name": asset_id,
        "ip_address": f"10.150.{ip_subnet}.{ip_host}",
        "environment": env,
        "trurisk_score": random.randint(40, 95),
        "vulnerabilities": [
            {
                "cve_id": cve_id,
                "severity": random.choice(["Critical", "High", "Medium"]),
                "cve_score": round(random.uniform(5.0, 10.0), 1),
                "status": "Active",
                "validation_proof": "None",
                "remediation_status": "Pending",
                "last_scan": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        ]
    }
    return MOCK_ASSET_REGISTRY[asset_id]

# ------------------------------------------------------------------------------
# MCP Resources
# ------------------------------------------------------------------------------

@mcp.resource("telemetry://active-session-logs/{asset_id}")
def get_active_session_logs(asset_id: str) -> str:
    """
    Returns the real-time security assessment telemetry and live vulnerability profiles
    for a specific digital asset. Helps the AI agent see TruRisk scores and CVEs.
    """
    logger.info(f"Resource telemetry requested for asset: {asset_id}")
    
    # In live mode, this would query the Qualys Cloud Agent API
    api_mode = os.getenv("QUALYS_API_MODE", "mock").lower()
    
    if api_mode == "live":
        # Simulate live API request (or connect using credentials)
        # For prototype fallback we route to our stateful registry
        pass
        
    asset_data = get_or_create_asset(asset_id)
    return json.dumps(asset_data, indent=2)


@mcp.resource("config://governance/autonomy-matrix")
def get_governance_autonomy_matrix() -> str:
    """
    Provides the central governance rules, approved remediation windows, 
    and auto-remediation policies. AI agents must inspect this to respect guardrails.
    """
    logger.info("Resource governance autonomy matrix requested.")
    matrix_path = os.getenv("GOVERNANCE_MATRIX_PATH", "governance_matrix.json")
    
    try:
        if os.path.exists(matrix_path):
            with open(matrix_path, "r") as f:
                data = json.load(f)
            return json.dumps(data, indent=2)
        else:
            logger.warning(f"Governance file not found at {matrix_path}. Using fallback default schema.")
    except Exception as e:
        logger.error(f"Error reading governance matrix: {e}")

    # Fallback structure
    fallback = {
        "policy_metadata": {"name": "Default Fallback Policy", "version": "1.0.0"},
        "safety_levels": {
            "high_risk_assets": {"requires_manual_approval": True, "allowed_remediation_actions": ["patch"]}
        },
        "maintenance_windows": {"enabled": False}
    }
    return json.dumps(fallback, indent=2)

# ------------------------------------------------------------------------------
# MCP Tools
# ------------------------------------------------------------------------------

@mcp.tool()
def delegate_validation_workflow(asset_id: str, cve_id: str) -> str:
    """
    Invokes TruConfirm to perform a safe, cryptographic, non-destructive execution validation check.
    Proves whether a vulnerability is actively exploitable on the target host.
    """
    logger.info(f"Tool execution requested: TruConfirm validation for {cve_id} on {asset_id}")
    
    asset = get_or_create_asset(asset_id)
    target_vuln = None
    for vuln in asset["vulnerabilities"]:
        if vuln["cve_id"].upper() == cve_id.upper():
            target_vuln = vuln
            break
            
    if not target_vuln:
        return f"Error: Vulnerability {cve_id} is not flagged or active on asset {asset_id}."

    # Simulate validation logic
    success_rate = 0.85 if asset["environment"] == "Production" else 0.50
    is_exploitable = random.random() < success_rate

    if is_exploitable:
        target_vuln["status"] = "Validated"
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        proof = (
            f"[TruConfirm Exploit Proof - {timestamp}]\n"
            f"Target URL: http://{asset['ip_address']}:8080/cgi-bin/php-cgi\n"
            f"Test Payload: ?%2d%64+allow%5furl%5finclude%3d1+%2d%64+auto%5fprepend%5ffile%3dphp://input\n"
            f"Execution Evidence: Remote Command Execution verified via non-destructive check.\n"
            f"Response Context: Out-of-band request received back from {asset['ip_address']}.\n"
            f"Exploit Path: Active, highly exploitable, remote shell path confirmed."
        )
        target_vuln["validation_proof"] = proof
        
        result_message = {
            "status": "EXPLOIT_VERIFIED",
            "message": f"TruConfirm successfully executed validation. Exploit path is viable for {cve_id}.",
            "asset": asset_id,
            "ip": asset["ip_address"],
            "trurisk_score": asset["trurisk_score"],
            "evidence": proof
        }
    else:
        target_vuln["status"] = "Active"
        target_vuln["validation_proof"] = "Checked: Validation script run, exploit path could not be completed (e.g. mitigations present)."
        
        result_message = {
            "status": "EXPLOIT_UNCONFIRMED",
            "message": f"TruConfirm executed validation for {cve_id}. The vulnerability is present, but active exploitation was blocked or failed.",
            "asset": asset_id,
            "ip": asset["ip_address"],
            "trurisk_score": asset["trurisk_score"],
            "evidence": "No dynamic exploit path validated under non-destructive triggers."
        }

    return json.dumps(result_message, indent=2)


@mcp.tool()
def orchestrate_remediation(asset_id: str, action_type: str, change_control_id: str) -> str:
    """
    Orchestrates remediation via TruRisk Eliminate and the Qualys Cloud Agent.
    Available actions:
      - 'patch': Installs the required vendor security patches.
      - 'mitigate_config': Applies localized configuration workarounds (e.g., unbinding ports or altering registry parameters).
      - 'network_isolate': Quarantines the device on the network while retaining administrative SOC access.
    Automatically binds the action to the provided change_control_id audit token.
    """
    logger.info(f"Tool execution requested: TruRisk Eliminate ({action_type}) on {asset_id} with Ticket ID {change_control_id}")
    
    asset = get_or_create_asset(asset_id)
    action_type = action_type.lower()
    
    if action_type not in ["patch", "mitigate_config", "network_isolate"]:
        return f"Error: Invalid action_type '{action_type}'. Must be 'patch', 'mitigate_config', or 'network_isolate'."

    # Load governance matrix to verify window (just log approval details)
    logger.info(f"Validating change-control {change_control_id} against central governance...")
    
    # Process stateful remediation in-memory
    active_vulns = [v for v in asset["vulnerabilities"] if v["status"] in ["Active", "Validated"]]
    
    if not active_vulns:
        return json.dumps({
            "status": "NO_ACTION_REQUIRED",
            "message": f"No active or validated vulnerabilities requiring remediation found on asset {asset_id}.",
            "asset": asset_id
        }, indent=2)

    remediated_cves = []
    for vuln in active_vulns:
        vuln["status"] = "Remediated"
        vuln["remediation_status"] = "Success"
        remediated_cves.append(vuln["cve_id"])

    # Calculate new risk score dynamically
    old_risk = asset["trurisk_score"]
    # Drop score by 40-60%, minimum risk of 15
    new_risk = max(15, int(old_risk * 0.35))
    asset["trurisk_score"] = new_risk

    execution_report = {
        "status": "REMEDIATION_SUCCESSFUL",
        "message": f"TruRisk Eliminate completed action ({action_type}) via Cloud Agent.",
        "asset": asset_id,
        "ip_address": asset["ip_address"],
        "audit_trail": {
            "change_control_id": change_control_id,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "agent_ram_overhead": "4.8 MB",
            "agent_cpu_utilisation": "< 0.5%",
            "network_egress_bytes": "128 KB"
        },
        "remediation_details": {
            "action_executed": action_type,
            "cves_remediated": remediated_cves
        },
        "risk_impact": {
            "previous_trurisk_score": old_risk,
            "current_trurisk_score": new_risk,
            "risk_reduction": f"{(1 - (new_risk / old_risk)) * 100:.1f}%"
        }
    }

    return json.dumps(execution_report, indent=2)

# ------------------------------------------------------------------------------
# MCP Prompts (Collaboration Templates)
# ------------------------------------------------------------------------------

@mcp.prompt()
def pre_flight_blast_radius(asset_id: str, cve_id: str) -> str:
    """
    Returns an interactive blast-radius template that guides the AI agent on how to preview
    patch risks, governance policies, and prepare the project manager approval request card.
    """
    logger.info(f"Prompt template 'pre-flight-blast-radius' generated for {cve_id} on {asset_id}")
    
    return f"""
System Checklist & Pre-Flight Blast Radius Assessment
--------------------------------------------------------------------------------
Asset ID: {asset_id}
CVE Target: {cve_id}
Recommended Mitigation: Cloud Agent remediation (TruRisk Eliminate)
--------------------------------------------------------------------------------

Dear AI Assistant,

Please prepare a formatted card to display to the Engineering Manager for approval of remediation actions on {asset_id}. Your analysis should answer:

1. **Governance Boundary Assessment**:
   - Query resource `config://governance/autonomy-matrix` and verify if {asset_id} requires manual approval.
   - Confirm if the current time fits within an allowed maintenance window.

2. **Impact & Blast Radius Details**:
   - Check resource `telemetry://active-session-logs/{asset_id}` to retrieve the active TruRisk score.
   - Explain the business risk of {cve_id} (e.g., Remote Code Execution, Privileges Escalation).
   - What are the potential network/system side effects? (Note: Qualys Cloud Agent remediation utilizes <5MB RAM and near-zero CPU).

3. **Remediation Execution Proposal**:
   - Propose invoking the tool `orchestrate_remediation` with `asset_id="{asset_id}"`, specifying the change ticket ID, and requesting a click-to-approve confirmation.
"""

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting Agent Val MCP Server on standard I/O (stdio)...")
    mcp.run()
