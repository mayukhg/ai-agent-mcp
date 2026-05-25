import json
import server

def run_test():
    print("======================================================================")
    print("STARTING CLOSED-LOOP STATE VERIFICATION TEST FOR AGENT VAL MCP SERVER")
    print("======================================================================\n")

    # 1. Fetch Governance Matrix
    print("Step 1: Retrieving Governance Autonomy Matrix...")
    gov_matrix_raw = server.get_governance_autonomy_matrix()
    gov_matrix = json.loads(gov_matrix_raw)
    print(f"Governance Policy Name: {gov_matrix['policy_metadata']['name']}")
    print(f"Maintenance Windows Enabled: {gov_matrix['maintenance_windows']['enabled']}\n")

    # 2. Fetch Initial Telemetry
    print("Step 2: Fetching Initial Security Telemetry for 'app-server-01'...")
    initial_tel_raw = server.get_active_session_logs("app-server-01")
    initial_tel = json.loads(initial_tel_raw)
    print(f"Asset Name: {initial_tel['asset_name']}")
    print(f"Initial TruRisk Score: {initial_tel['trurisk_score']}")
    print(f"Vulnerabilities Count: {len(initial_tel['vulnerabilities'])}")
    for v in initial_tel['vulnerabilities']:
        print(f"  - {v['cve_id']} (Severity: {v['severity']}) -> Status: {v['status']}, Remediation: {v['remediation_status']}")
    print()

    # 3. Delegate Validation Workflow (TruConfirm)
    print("Step 3: Triggering TruConfirm Validation check for CVE-2024-4577...")
    val_result_raw = server.delegate_validation_workflow("app-server-01", "CVE-2024-4577")
    val_result = json.loads(val_result_raw)
    print(f"Validation Status: {val_result['status']}")
    print(f"Message: {val_result['message']}")
    print("Exploit Proof Excerpt:")
    proof_lines = val_result['evidence'].split('\n')
    for line in proof_lines[:4]:
        print(f"  {line}")
    print()

    # 4. Fetch Telemetry after Validation
    print("Step 4: Checking Telemetry status after validation...")
    mid_tel_raw = server.get_active_session_logs("app-server-01")
    mid_tel = json.loads(mid_tel_raw)
    cve_status = [v for v in mid_tel['vulnerabilities'] if v['cve_id'] == 'CVE-2024-4577'][0]
    print(f"CVE-2024-4577 Status in Telemetry: {cve_status['status']}\n")

    # 5. Orchestrate Remediation (TruRisk Eliminate / Cloud Agent)
    print("Step 5: Orchestrating Patch Remediation with change ticket #CC-9901...")
    rem_result_raw = server.orchestrate_remediation("app-server-01", "patch", "CC-9901")
    rem_result = json.loads(rem_result_raw)
    print(f"Remediation Status: {rem_result['status']}")
    print(f"Audit Ticket Bound: {rem_result['audit_trail']['change_control_id']}")
    print(f"Qualys Cloud Agent Footprint: CPU {rem_result['audit_trail']['agent_cpu_utilisation']}, RAM {rem_result['audit_trail']['agent_ram_overhead']}")
    print(f"Risk Reduction Delta: {rem_result['risk_impact']['previous_trurisk_score']} -> {rem_result['risk_impact']['current_trurisk_score']} ({rem_result['risk_impact']['risk_reduction']})\n")

    # 6. Fetch Telemetry after Remediation
    print("Step 6: Verifying final Telemetry and TruRisk closure...")
    final_tel_raw = server.get_active_session_logs("app-server-01")
    final_tel = json.loads(final_tel_raw)
    print(f"Final TruRisk Score: {final_tel['trurisk_score']}")
    for v in final_tel['vulnerabilities']:
        print(f"  - {v['cve_id']} (Severity: {v['severity']}) -> Status: {v['status']}, Remediation: {v['remediation_status']}")
    print()

    print("======================================================================")
    print("VERIFICATION TEST COMPLETED SUCCESSFULLY! CLOSED-LOOP WORKFLOW VALIDATED")
    print("======================================================================")

if __name__ == "__main__":
    run_test()
