/* ==============================================================================
   Security Sentinel GUI Event & Loop Controller (Selector & Chat Ready)
   ============================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  // Mode Selection Elements
  const landingSplash = document.getElementById("landing-splash");
  const choiceDashboard = document.getElementById("choice-dashboard");
  const choiceChat = document.getElementById("choice-chat");
  const btnToggleInterface = document.getElementById("btn-toggle-interface");
  const activeModeBadge = document.getElementById("active-mode-badge");
  const headerStatusPulse = document.getElementById("header-status-pulse");
  
  // Viewports
  const dashboardViewport = document.getElementById("dashboard-viewport");
  const chatViewport = document.getElementById("chat-viewport");

  // Core ETM Elements
  const govPolicyName = document.getElementById("gov-policy-name");
  const govChangeWindow = document.getElementById("gov-change-window");
  const assetsContainer = document.getElementById("assets-container");
  const consoleLogs = document.getElementById("console-logs");
  const btnRefresh = document.getElementById("btn-refresh");
  
  // Conversational Chat Elements
  const chatMessagesContainer = document.getElementById("chat-messages-container");
  const chatTypingIndicator = document.getElementById("chat-typing-indicator");
  const chatInputForm = document.getElementById("chat-input-form");
  const chatMessageInput = document.getElementById("chat-message-input");
  const chatPostureList = document.getElementById("chat-posture-list");
  const suggestButtons = document.querySelectorAll(".btn-suggest");

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
  let activeAgentMode = ""; // 'dashboard' or 'chat'

  // Helpers
  const addLog = (message, type = "info") => {
    const time = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = `log-line ${type}`;
    line.textContent = `[${time}] ${message}`;
    consoleLogs.appendChild(line);
    consoleLogs.scrollTop = consoleLogs.scrollHeight;
  };

  // ------------------------------------------------------------------------------
  // 1. Selector Landing Page & Switching Controller
  // ------------------------------------------------------------------------------

  const selectAgentMode = (mode) => {
    activeAgentMode = mode;
    landingSplash.classList.add("hidden");
    addLog(`Agent mode selected: ${mode.toUpperCase()}`, "sys");

    if (mode === "dashboard") {
      dashboardViewport.classList.remove("hidden");
      chatViewport.classList.add("hidden");
      activeModeBadge.textContent = "Visual Dashboard Grid";
      activeModeBadge.style.borderColor = "#6366f1";
      headerStatusPulse.style.backgroundColor = "#6366f1";
    } else {
      chatViewport.classList.remove("hidden");
      dashboardViewport.classList.add("hidden");
      activeModeBadge.textContent = "Conversational Chat";
      activeModeBadge.style.borderColor = "#06b6d4";
      headerStatusPulse.style.backgroundColor = "#06b6d4";
      addLog("[AI Sentinel] Conversational chat session started. Ready for your plain language ETM commands.", "info");
      
      // Auto scroll chat to bottom
      chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
    }
    
    // Ingest latest state
    fetchAssets(true);
  };

  choiceDashboard.addEventListener("click", () => selectAgentMode("dashboard"));
  choiceChat.addEventListener("click", () => selectAgentMode("chat"));
  
  btnToggleInterface.addEventListener("click", () => {
    landingSplash.classList.remove("hidden");
    addLog("Returning to Agent Selection Landing Portal...", "sys");
  });

  // ------------------------------------------------------------------------------
  // 2. Fetch Governance Matrix
  // ------------------------------------------------------------------------------
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

  // ------------------------------------------------------------------------------
  // 3. Fetch ETM Telemetry (State Synchronized)
  // ------------------------------------------------------------------------------
  const fetchAssets = async (logSilence = false) => {
    try {
      if (!logSilence) addLog("Fetching active session telemetry from ETM...", "sys");
      const res = await fetch("/api/telemetry");
      if (!res.ok) throw new Error("API failure");
      assetsData = await res.json();
      
      renderAssetsGrid();
      renderCompactPostureSidebar();
      if (!logSilence) addLog(`Telemetry fetched for ${Object.keys(assetsData).length} active hosts.`, "success");
    } catch (err) {
      addLog(`Failed to query telemetry logs: ${err.message}`, "danger");
    }
  };

  // ------------------------------------------------------------------------------
  // 4. Render Layout Viewports
  // ------------------------------------------------------------------------------

  // Viewport A: Telemetry Grid Cards
  const renderAssetsGrid = () => {
    if (!assetsContainer) return;
    assetsContainer.innerHTML = "";
    
    Object.keys(assetsData).forEach(id => {
      const asset = assetsData[id];
      const isSelected = id === selectedAssetId;
      const primaryCve = asset.vulnerabilities[0];
      
      const card = document.createElement("div");
      card.className = `card glass asset-card ${isSelected ? 'active-selection' : ''}`;
      card.dataset.id = id;
      
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

      card.addEventListener("click", (e) => {
        if (e.target.tagName !== "BUTTON") {
          selectedAssetId = id;
          document.querySelectorAll(".asset-card").forEach(c => c.classList.remove("active-selection"));
          card.classList.add("active-selection");
          addLog(`Focused console telemetry window on asset: ${id}`, "info");
        }
      });

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

  // Viewport B: Chat Posture Sidebar (Compact List)
  const renderCompactPostureSidebar = () => {
    if (!chatPostureList) return;
    chatPostureList.innerHTML = "";
    
    Object.keys(assetsData).forEach(id => {
      const asset = assetsData[id];
      const primaryCve = asset.vulnerabilities[0];
      
      let riskClass = "success";
      if (asset.trurisk_score > 80) riskClass = "danger";
      else if (asset.trurisk_score > 40) riskClass = "warning";

      const item = document.createElement("div");
      item.className = "posture-item";
      item.innerHTML = `
        <div class="posture-meta">
          <h5>${asset.asset_name}</h5>
          <span>CVE: ${primaryCve.cve_id} (${primaryCve.status})</span>
        </div>
        <span class="posture-score ${riskClass}">${asset.trurisk_score}</span>
      `;
      chatPostureList.appendChild(item);
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

  // ------------------------------------------------------------------------------
  // 5. Visual Dashboard Actions
  // ------------------------------------------------------------------------------

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

  const validateVulnerability = async (assetId, cveId, cardElement) => {
    addLog(`Initiating TruConfirm exploit validation for ${cveId} on ${assetId}...`, "sys");
    addLog(`[AI Agent] Connecting via MCP Client. Spawning delegate_validation_workflow(asset_id="${assetId}", cve_id="${cveId}")...`, "info");
    
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
      
      result.evidence.split("\n").forEach(line => {
        addLog(`  ${line}`, "success");
      });

      await fetchAssets(true);

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

  // ------------------------------------------------------------------------------
  // 6. Conversational Chat Engine (API REST integrations)
  // ------------------------------------------------------------------------------

  // Render Bot Response bubble
  const appendMessage = (sender, text, type = "bot", isPreformatted = false) => {
    const bubble = document.createElement("div");
    bubble.className = `message-bubble ${type}`;
    
    const header = document.createElement("div");
    header.className = "message-sender";
    header.textContent = sender;
    
    const messageText = document.createElement("div");
    messageText.className = "message-text";
    
    if (isPreformatted) {
      const pre = document.createElement("pre");
      pre.textContent = text;
      messageText.appendChild(pre);
    } else {
      // Basic formatting of newlines and bold markers
      let formatted = text.replace(/\n/g, "<br>");
      formatted = formatted.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
      formatted = formatted.replace(/`(.*?)`/g, "<code>$1</code>");
      messageText.innerHTML = formatted;
    }
    
    bubble.appendChild(header);
    bubble.appendChild(messageText);
    
    chatMessagesContainer.appendChild(bubble);
    chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
  };

  // Submit chat query
  const submitChatQuery = async (queryText) => {
    if (!queryText) return;
    
    appendMessage("You", queryText, "user");
    chatMessageInput.value = "";
    
    // Show Typing indicator
    chatTypingIndicator.classList.remove("hidden");
    chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;

    try {
      addLog(`Sending conversational query to Sentinel Agent...`, "sys");
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: queryText })
      });
      
      if (!res.ok) throw new Error("Agent response error");
      const data = await res.json();
      
      // Hide typing
      chatTypingIndicator.classList.add("hidden");
      
      // Append bot chat reply
      appendMessage("Security Sentinel [AI]", data.reply, "bot");
      
      // If the backend triggered ETM tools, let's output evidence preformatted!
      if (data.evidence) {
        appendMessage("TruConfirm [MCP Proof]", data.evidence, "bot", true);
      }
      
      // If the backend processed an active remediation, pop open the HITL modal!
      if (data.trigger_approval) {
        selectedAssetId = data.asset_id;
        currentValidatingCve = data.cve_id;
        openHITLModal(data.asset_id, data.cve_id, data.evidence);
      }

      // Sync telemetry
      await fetchAssets(true);

    } catch (err) {
      chatTypingIndicator.classList.add("hidden");
      appendMessage("Security Sentinel [AI]", `Error: I encountered a connection issue. ${err.message}`, "bot");
      addLog(`Chat session endpoint failure: ${err.message}`, "danger");
    }
  };

  chatInputForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const query = chatMessageInput.value.trim();
    submitChatQuery(query);
  });

  // Suggested Prompts click binders
  suggestButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      // Strip search/mitigation emojis and load query
      const queryText = btn.textContent.replace(/^[^\w]*/, "").trim();
      submitChatQuery(queryText);
    });
  });

  // ------------------------------------------------------------------------------
  // 7. Human-in-the-Loop Modal Gating
  // ------------------------------------------------------------------------------
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

  const executeRemediation = async () => {
    const assetId = modalAssetId.textContent;
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

      // Append confirmation bubble to chat if in chat mode
      if (activeAgentMode === "chat") {
        appendMessage("Security Sentinel [AI]", `Mitigation completed successfully!<br><br>• <strong>Asset</strong>: ${assetId}<br>• <strong>Action</strong>: Patch deployed via Cloud Agent<br>• <strong>TruRisk reduction</strong>: ${report.risk_impact.previous_trurisk_score} ➔ ${report.risk_impact.current_trurisk_score}<br>• <strong>Audit ticket</strong>: #${ticketId} closed successfully.`, "bot");
      }

      await fetchAssets(true);
      closeHITLModal();

    } catch (err) {
      addLog(`Remediation execution failed: ${err.message}`, "danger");
      if (activeAgentMode === "chat") {
        appendMessage("Security Sentinel [AI]", `Error deploying patch: ${err.message}`, "bot");
      }
    } finally {
      btnApprove.innerHTML = "Authorize Patch Execution";
      btnApprove.disabled = false;
    }
  };

  // Event Bindings
  btnRefresh.addEventListener("click", () => fetchAssets());
  btnCloseModal.addEventListener("click", closeHITLModal);
  btnDecline.addEventListener("click", closeHITLModal);
  btnApprove.addEventListener("click", executeRemediation);

  // Initialize
  const init = async () => {
    await fetchGovernance();
    // Default load choice portal (doesn't fetch assets until a viewport is picked)
    landingSplash.classList.remove("hidden");
  };

  init();
});
