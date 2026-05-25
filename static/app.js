/* ==============================================================================
   Security Sentinel GUI Event & Loop Controller
   ============================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const govPolicyName = document.getElementById("gov-policy-name");
  const govChangeWindow = document.getElementById("gov-change-window");
  const assetsContainer = document.getElementById("assets-container");
  const consoleLogs = document.getElementById("console-logs");
  const btnRefresh = document.getElementById("btn-refresh");
  
  // Modal Elements
  const hitlModal = document.getElementById("hitl-modal");
  const modalAssetId = document.getElementById("modal-asset-id");
  const modalCveId = document.getElementById("modal-cve-id");
  const exploitEvidence = document.getElementById("exploit-evidence");
  const changeTicketId = document.getElementById("change-ticket-id");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const btnDecline = document.getElementById("btn-decline");
  const btnApprove = document.getElementById("btn-approve");

  // State Variables
  let assetsData = {};
  let selectedAssetId = "app-server-01"; // Default focus
  let currentValidatingCve = "CVE-2024-4577";

  // Helpers
  const addLog = (message, type = "info") => {
    const time = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = `log-line ${type}`;
    line.textContent = `[${time}] ${message}`;
    consoleLogs.appendChild(line);
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
  };

  // 1. Fetch Governance Matrix
  const fetchGovernance = async () => {
    try {
      addLog("Querying config://governance/autonomy-matrix...", "sys");
      const res = await fetch("/api/governance");
      if (!res.ok) throw new Error("API failure");
      const data = await res.json();
      
      govPolicyName.textContent = data.policy_metadata.name;
      govChangeWindow.textContent = data.maintenance_windows.enabled ? "Authorized (Sat/Sun Window)" : "Always Allowed";
      addLog(`Governance policy parsed successfully: ${data.policy_metadata.name}`, "success");
    } catch (err) {
      addLog(`Failed to query governance rules: ${err.message}`, "danger");
      govPolicyName.textContent = "Governance Mode: Local Off";
      govChangeWindow.textContent = "Offline Fallback";
    }
  };

  // 2. Fetch Assets Telemetry
  const fetchAssets = async (logSilence = false) => {
    try {
      if (!logSilence) addLog("Fetching active session telemetry from ETM...", "sys");
      const res = await fetch("/api/telemetry");
      if (!res.ok) throw new Error("API failure");
      assetsData = await res.json();
      
      renderAssetsGrid();
      if (!logSilence) addLog(`Telemetry fetched for ${Object.keys(assetsData).length} active hosts.`, "success");
    } catch (err) {
      addLog(`Failed to query telemetry logs: ${err.message}`, "danger");
    }
  };

  // 3. Render Asset Grid
  const renderAssetsGrid = () => {
    assetsContainer.innerHTML = "";
    
    Object.keys(assetsData).forEach(id => {
      const asset = assetsData[id];
      const isSelected = id === selectedAssetId;
      const primaryCve = asset.vulnerabilities[0];
      
      const card = document.createElement("div");
      card.className = `card glass asset-card ${isSelected ? 'active-selection' : ''}`;
      card.dataset.id = id;
      
      // Classify risk badge color
      let riskClass = "success";
      if (asset.trurisk_score > 80) riskClass = "danger";
      else if (asset.trurisk_score > 40) riskClass = "warning";

      card.innerHTML = `
        <div class="asset-header">
          <div class="asset-title">
            <h4>${asset.asset_name}</h4>
            <span>${asset.ip_address}</span>
          </div>
          <span class="risk-badge ${riskClass}">TRURISK: ${asset.trurisk_score}</span>
        </div>
        <div class="asset-details">
          <span><strong>Env:</strong> ${asset.environment}</span>
          <span><strong>Vulnerabilities:</strong> ${asset.vulnerabilities.length} active</span>
          <span><strong>Primary threat:</strong> <span class="font-danger">${primaryCve.cve_id}</span></span>
          <span><strong>CVE status:</strong> <span class="${getStatusColorClass(primaryCve.status)}">${primaryCve.status}</span></span>
        </div>
        <div class="asset-actions">
          <button class="btn btn-secondary btn-check-telemetry">Check telemetry</button>
          ${primaryCve.status === "Remediated" 
            ? `<button class="btn btn-success" disabled>✓ Patched</button>` 
            : `<button class="btn btn-primary btn-validate-exploit">Validate Exploit</button>`
          }
        </div>
      `;

      // Select Card Focus
      card.addEventListener("click", (e) => {
        if (e.target.tagName !== "BUTTON") {
          selectedAssetId = id;
          document.querySelectorAll(".asset-card").forEach(c => c.classList.remove("active-selection"));
          card.classList.add("active-selection");
          addLog(`Focused console telemetry window on asset: ${id}`, "info");
        }
      });

      // Actions bind
      card.querySelector(".btn-check-telemetry").addEventListener("click", () => {
        selectedAssetId = id;
        checkTelemetry(id);
      });

      const btnValidate = card.querySelector(".btn-validate-exploit");
      if (btnValidate) {
        btnValidate.addEventListener("click", () => {
          selectedAssetId = id;
          currentValidatingCve = primaryCve.cve_id;
          validateVulnerability(id, primaryCve.cve_id, card);
        });
      }

      assetsContainer.appendChild(card);
    });
  };

  const getStatusColorClass = (status) => {
    switch (status) {
      case "Active": return "font-danger";
      case "Validated": return "font-warning";
      case "Remediated": return "font-success";
      default: return "font-highlight";
    }
  };

  // 4. Action: Check Telemetry
  const checkTelemetry = async (assetId) => {
    addLog(`Ingesting resource logs telemetry://active-session-logs/${assetId}...`, "sys");
    const asset = assetsData[assetId];
    if (!asset) return;
    
    addLog(`[AI Analysis] Host: ${asset.asset_name} is running in ${asset.environment} at IP ${asset.ip_address}.`, "info");
    addLog(`[AI Analysis] Current TruRisk Score is ${asset.trurisk_score}. Active vulnerability alerts:`, "info");
    asset.vulnerabilities.forEach(v => {
      addLog(`  -> ${v.cve_id} (Score: ${v.cve_score}, Status: ${v.status}, Remediation: ${v.remediation_status})`, "warning");
    });
  };

  // 5. Action: Validate Vulnerability (TruConfirm tool)
  const validateVulnerability = async (assetId, cveId, cardElement) => {
    addLog(`Initiating TruConfirm exploit validation for ${cveId} on ${assetId}...`, "sys");
    addLog(`[AI Agent] Connecting via MCP Client. Spawning delegate_validation_workflow(asset_id="${assetId}", cve_id="${cveId}")...`, "info");
    
    // UI Loading state in button
    const btn = cardElement.querySelector(".btn-validate-exploit");
    const originalText = btn.innerHTML;
    btn.innerHTML = `<span class="spinner-inline"></span> Executing Check...`;
    btn.disabled = true;

    try {
      const res = await fetch("/api/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ asset_id: assetId, cve_id: cveId })
      });
      
      if (!res.ok) throw new Error("Validation trigger failed");
      const result = await res.json();

      addLog(`TruConfirm Completed! Status: ${result.status}`, "success");
      addLog(`[MCP Output] Exploit verification evidence trail:`, "success");
      
      // Print first few evidence lines
      result.evidence.split("\n").forEach(line => {
        addLog(`  ${line}`, "success");
      });

      // Stateful reload assets
      await fetchAssets(true);

      // Open Gating Modal
      setTimeout(() => {
        openHITLModal(assetId, cveId, result.evidence);
      }, 1000);

    } catch (err) {
      addLog(`TruConfirm validation failed: ${err.message}`, "danger");
    } finally {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  };

  // 6. HITL Modal Gating
  const openHITLModal = (assetId, cveId, evidenceText) => {
    modalAssetId.textContent = assetId;
    modalCveId.textContent = cveId;
    exploitEvidence.textContent = evidenceText;
    
    addLog(`[AI Sentinel Gating] Autonomy safety matrix requires manual manager authorization to apply remediation patches. Rendering approval modal.`, "warning");
    
    hitlModal.classList.remove("hidden");
  };

  const closeHITLModal = () => {
    hitlModal.classList.add("hidden");
    addLog(`HITL approval modal dismissed.`, "info");
  };

  // 7. Action: Remediate (TruRisk Eliminate / Cloud Agent)
  const executeRemediation = async () => {
    const assetId = modalAssetId.textContent;
    const cveId = modalCveId.textContent;
    const ticketId = changeTicketId.value.trim() || "CC-9942";

    addLog(`[HITL Approved] Authorizing patch remediation. Change Control Ticket ID: ${ticketId}`, "success");
    addLog(`Calling MCP tool orchestrate_remediation(asset_id="${assetId}", action_type="patch", change_control_id="${ticketId}")...`, "sys");
    
    btnApprove.innerHTML = `Deploying Patch...`;
    btnApprove.disabled = true;

    try {
      const res = await fetch("/api/remediate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ asset_id: assetId, action_type: "patch", change_control_id: ticketId })
      });
      
      if (!res.ok) throw new Error("Remediation execution failed");
      const report = await res.json();

      addLog(`[MCP Output] TruRisk Eliminate completed! Status: ${report.status}`, "success");
      addLog(`[Qualys Cloud Agent Footprint] RAM overhead: ${report.audit_trail.agent_ram_overhead}, CPU utilization: ${report.audit_trail.agent_cpu_utilisation}`, "info");
      addLog(`[Risk Reduction Report] TruRisk decreased statefully from ${report.risk_impact.previous_trurisk_score} to ${report.risk_impact.current_trurisk_score} (Reduction of ${report.risk_impact.risk_reduction})`, "success");
      addLog(`[Audit Log] Change control ticket #${ticketId} statefully verified, closed, and registered in centralized reporting log.`, "success");

      // Reload state in dashboard
      await fetchAssets(true);
      closeHITLModal();

    } catch (err) {
      addLog(`Remediation execution failed: ${err.message}`, "danger");
    } finally {
      btnApprove.innerHTML = "Authorize Patch Execution";
      btnApprove.disabled = false;
    }
  };

  // Event Listeners bind
  btnRefresh.addEventListener("click", () => fetchAssets());
  btnCloseModal.addEventListener("click", closeHITLModal);
  btnDecline.addEventListener("click", closeHITLModal);
  btnApprove.addEventListener("click", executeRemediation);

  // Initialize
  const init = async () => {
    await fetchGovernance();
    await fetchAssets();
  };

  init();
});
