const API_URL = "http://127.0.0.1:8000";


// ============================================================
// API HELPER
// ============================================================

async function apiRequest(url, options = {}) {
    const response = await fetch(url, options);

    if (!response.ok) {
        const message = await response.text();
        throw new Error(
            `API ${response.status}: ${message}`
        );
    }

    return await response.json();
}


// ============================================================
// PAGE LOAD
// ============================================================

document.addEventListener("DOMContentLoaded", () => {
    checkServer();
    loadDashboard();
});


// ============================================================
// CHECK SERVER
// ============================================================

async function checkServer() {
    const status = document.getElementById("serverStatus");

    try {
        await apiRequest(`${API_URL}/`);

        if (status) {
            status.textContent = "API Online";
        }

    } catch (error) {

        if (status) {
            status.textContent = "API Offline";
        }

        console.error(error);
    }
}


// ============================================================
// LOAD COMPLETE DASHBOARD
// ============================================================

async function loadDashboard() {
    await loadSummary();
    await loadThreatTypes();
    await loadRiskLevels();
    await loadTrends();
    await loadRecentAttacks();
    await loadIncidents();
}


// ============================================================
// SUMMARY
// ============================================================

async function loadSummary() {
    try {

        const data = await apiRequest(
            `${API_URL}/dashboard/summary`
        );

        setText(
            "totalThreats",
            data.total_threats
        );

        setText(
            "highRiskThreats",
            data.high_risk_threats
        );

        setText(
            "openIncidents",
            data.open_incidents
        );

        setText(
            "resolvedIncidents",
            data.resolved_incidents
        );

    } catch (error) {

        console.error(
            "Summary error:",
            error
        );
    }
}


// ============================================================
// ANALYZE THREAT
// ============================================================

async function analyzeThreat() {

    const threatType =
        document.getElementById(
            "threatType"
        ).value;

    const threatValue =
        document.getElementById(
            "threatValue"
        ).value.trim();

    const resultBox =
        document.getElementById(
            "threatResult"
        );

    if (!threatValue) {

        resultBox.className =
            "result-box warning";

        resultBox.classList.remove("hidden");

        resultBox.innerHTML =
            "<strong>Please enter a threat value.</strong>";

        return;
    }


    resultBox.className =
        "result-box";

    resultBox.classList.remove("hidden");

    resultBox.innerHTML =
        "Analyzing threat...";


    try {

        const data = await apiRequest(
            `${API_URL}/threat`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    threat_type: threatType,
                    threat_value: threatValue
                })
            }
        );


        resultBox.className =
            "result-box success";


        resultBox.innerHTML = `

            <div class="result-title">
                Threat Recorded Successfully
            </div>

            <div class="result-row">
                <span>Threat ID</span>
                <span>${escapeHTML(data.threat_id)}</span>
            </div>

            <div class="result-row">
                <span>Threat Type</span>
                <span>${escapeHTML(data.threat_type)}</span>
            </div>

            <div class="result-row">
                <span>Threat Value</span>
                <span>${escapeHTML(data.threat_value)}</span>
            </div>

            <div class="result-row">
                <span>Result</span>
                <span>${escapeHTML(data.result)}</span>
            </div>

            <div class="result-row">
                <span>Risk Level</span>
                <span class="${getRiskClass(data.risk_level)}">
                    ${escapeHTML(data.risk_level)}
                </span>
            </div>

            <div class="result-row">
                <span>Reason</span>
                <span>${escapeHTML(data.reason)}</span>
            </div>

            <div class="result-row">
                <span>SHA-256</span>
                <span>${escapeHTML(data.evidence_hash)}</span>
            </div>

            <div class="result-row">
                <span>Blockchain TX</span>
                <span>${escapeHTML(data.blockchain_tx)}</span>
            </div>
        `;


        document.getElementById(
            "verifyThreatId"
        ).value = data.threat_id;


        document.getElementById(
            "incidentThreatId"
        ).value = data.threat_id;


        await loadDashboard();


    } catch (error) {

        resultBox.className =
            "result-box danger";

        resultBox.innerHTML = `

            <div class="result-title">
                Threat Analysis Failed
            </div>

            <div>
                ${escapeHTML(error.message)}
            </div>
        `;

        console.error(error);
    }
}


// ============================================================
// VERIFY THREAT
// ============================================================

async function verifyThreat() {

    const threatId =
        document.getElementById(
            "verifyThreatId"
        ).value;


    const resultBox =
        document.getElementById(
            "verifyResult"
        );


    if (!threatId) {

        resultBox.className =
            "result-box warning";

        resultBox.classList.remove("hidden");

        resultBox.innerHTML =
            "<strong>Please enter a Threat ID.</strong>";

        return;
    }


    resultBox.className =
        "result-box";

    resultBox.classList.remove("hidden");

    resultBox.innerHTML =
        "Verifying blockchain evidence...";


    try {

        const data = await apiRequest(
            `${API_URL}/verify/${threatId}`
        );


        if (data.verified) {

            resultBox.className =
                "result-box success";

        } else {

            resultBox.className =
                "result-box danger";
        }


        resultBox.innerHTML = `

            <div class="result-title">
                ${
                    data.verified
                        ? "✓ Evidence Authentic"
                        : "⚠ Evidence Tampered"
                }
            </div>

            <div class="result-row">
                <span>Threat ID</span>
                <span>${escapeHTML(data.threat_id)}</span>
            </div>

            <div class="result-row">
                <span>Current Hash</span>
                <span>${escapeHTML(data.current_hash)}</span>
            </div>

            <div class="result-row">
                <span>Blockchain Hash</span>
                <span>${escapeHTML(data.blockchain_hash)}</span>
            </div>

            <div class="result-row">
                <span>Verified</span>
                <span>${data.verified}</span>
            </div>

            <div class="result-row">
                <span>Status</span>
                <span>${escapeHTML(data.status)}</span>
            </div>
        `;


    } catch (error) {

        resultBox.className =
            "result-box danger";

        resultBox.classList.remove("hidden");

        resultBox.innerHTML = `
            <div class="result-title">
                Verification Failed
            </div>

            <div>
                ${escapeHTML(error.message)}
            </div>
        `;

        console.error(error);
    }
}


// ============================================================
// THREAT TYPES
// ============================================================

async function loadThreatTypes() {

    const container =
        document.getElementById(
            "threatTypes"
        );


    try {

        const data = await apiRequest(
            `${API_URL}/dashboard/threat-types`
        );


        container.innerHTML = "";


        const entries =
            Object.entries(data);


        if (entries.length === 0) {

            container.innerHTML =
                '<div class="empty">No threat data.</div>';

            return;
        }


        entries.forEach(
            ([name, count]) => {

                const item =
                    document.createElement(
                        "div"
                    );

                item.className =
                    "distribution-item";

                item.innerHTML = `
                    <span class="distribution-name">
                        ${escapeHTML(name)}
                    </span>

                    <span class="distribution-count">
                        ${count}
                    </span>
                `;

                container.appendChild(item);
            }
        );


    } catch (error) {

        container.innerHTML =
            '<div class="empty">Unable to load threat types.</div>';

        console.error(error);
    }
}


// ============================================================
// RISK LEVELS
// ============================================================

async function loadRiskLevels() {

    const container =
        document.getElementById(
            "riskLevels"
        );


    try {

        const data = await apiRequest(
            `${API_URL}/dashboard/risk-levels`
        );


        container.innerHTML = "";


        const entries =
            Object.entries(data);


        if (entries.length === 0) {

            container.innerHTML =
                '<div class="empty">No risk data.</div>';

            return;
        }


        entries.forEach(
            ([name, count]) => {

                const item =
                    document.createElement(
                        "div"
                    );

                item.className =
                    "distribution-item";

                item.innerHTML = `
                    <span class="distribution-name ${getRiskClass(name)}">
                        ${escapeHTML(name)}
                    </span>

                    <span class="distribution-count">
                        ${count}
                    </span>
                `;

                container.appendChild(item);
            }
        );


    } catch (error) {

        container.innerHTML =
            '<div class="empty">Unable to load risk levels.</div>';

        console.error(error);
    }
}


// ============================================================
// TRENDS
// ============================================================

async function loadTrends() {

    const container =
        document.getElementById(
            "trends"
        );


    try {

        const data = await apiRequest(
            `${API_URL}/dashboard/trends`
        );


        container.innerHTML = "";


        if (!data.length) {

            container.innerHTML =
                '<div class="empty">No trend data.</div>';

            return;
        }


        let maxCount = 1;

        data.forEach(item => {

            if (item.threat_count > maxCount) {
                maxCount = item.threat_count;
            }
        });


        data.forEach(item => {

            const percentage =
                (
                    item.threat_count /
                    maxCount
                ) * 100;


            const div =
                document.createElement(
                    "div"
                );

            div.className =
                "trend-item";


            div.innerHTML = `

                <div class="trend-top">

                    <span>
                        ${escapeHTML(item.date)}
                    </span>

                    <strong>
                        ${item.threat_count}
                    </strong>

                </div>

                <div class="progress">

                    <div
                        class="progress-bar"
                        style="width:${percentage}%"
                    ></div>

                </div>
            `;


            container.appendChild(div);
        });


    } catch (error) {

        container.innerHTML =
            '<div class="empty">Unable to load trends.</div>';

        console.error(error);
    }
}


// ============================================================
// RECENT ATTACKS
// ============================================================

async function loadRecentAttacks() {

    const tbody =
        document.getElementById(
            "recentAttacksBody"
        );


    try {

        const data = await apiRequest(
            `${API_URL}/dashboard/recent-attacks`
        );


        tbody.innerHTML = "";


        if (!data.length) {

            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty">
                        No threats found.
                    </td>
                </tr>
            `;

            return;
        }


        data.forEach(threat => {

            const row =
                document.createElement(
                    "tr"
                );


            row.innerHTML = `

                <td>
                    ${escapeHTML(threat.id)}
                </td>

                <td>
                    ${escapeHTML(threat.threat_type)}
                </td>

                <td>
                    ${escapeHTML(threat.threat_value)}
                </td>

                <td class="${getRiskClass(threat.risk_level)}">
                    ${escapeHTML(threat.risk_level)}
                </td>

                <td>
                    ${escapeHTML(threat.status)}
                </td>

                <td
                    class="tx"
                    title="${escapeHTML(threat.blockchain_tx || "")}"
                >
                    ${escapeHTML(threat.blockchain_tx || "-")}
                </td>
            `;


            tbody.appendChild(row);
        });


    } catch (error) {

        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="empty">
                    Unable to load attacks.
                </td>
            </tr>
        `;

        console.error(error);
    }
}


// ============================================================
// CREATE INCIDENT
// ============================================================

async function createIncident() {

    const threatId =
        document.getElementById(
            "incidentThreatId"
        ).value;


    if (!threatId) {

        alert(
            "Please enter a Threat ID."
        );

        return;
    }


    try {

        const data = await apiRequest(
            `${API_URL}/incident`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    threat_id:
                        Number(threatId)
                })
            }
        );


        alert(
            `Incident #${data.incident_id} created successfully.`
        );


        await loadDashboard();


    } catch (error) {

        alert(
            `Incident creation failed:\n${error.message}`
        );

        console.error(error);
    }
}


// ============================================================
// LOAD INCIDENTS
// ============================================================

async function loadIncidents() {

    const tbody =
        document.getElementById(
            "incidentsBody"
        );


    try {

        const data = await apiRequest(
            `${API_URL}/incidents`
        );


        tbody.innerHTML = "";


        if (!data.length) {

            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty">
                        No incidents found.
                    </td>
                </tr>
            `;

            return;
        }


        data.forEach(incident => {

            const row =
                document.createElement(
                    "tr"
                );


            let action = "";


            if (incident.status === "Open") {

                action = `
                    <button
                        class="secondary-btn"
                        onclick="resolveIncident(${incident.id})"
                    >
                        Resolve
                    </button>
                `;

            } else {

                action = `
                    <span class="status-resolved">
                        Resolved
                    </span>
                `;
            }


            row.innerHTML = `

                <td>
                    ${escapeHTML(incident.id)}
                </td>

                <td>
                    ${escapeHTML(incident.threat_id)}
                </td>

                <td class="${
                    incident.status === "Open"
                        ? "status-open"
                        : "status-resolved"
                }">
                    ${escapeHTML(incident.status)}
                </td>

                <td>
                    ${formatDate(incident.created_at)}
                </td>

                <td>
                    ${
                        incident.resolved_at
                            ? formatDate(
                                incident.resolved_at
                            )
                            : "-"
                    }
                </td>

                <td>
                    ${action}
                </td>
            `;


            tbody.appendChild(row);
        });


    } catch (error) {

        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="empty">
                    Unable to load incidents.
                </td>
            </tr>
        `;

        console.error(error);
    }
}


// ============================================================
// RESOLVE INCIDENT
// ============================================================

async function resolveIncident(
    incidentId
) {

    try {

        const data = await apiRequest(
            `${API_URL}/incidents/${incidentId}/resolve`,
            {
                method: "PUT"
            }
        );


        alert(
            `Incident #${data.incident_id} resolved successfully.`
        );


        await loadDashboard();


    } catch (error) {

        alert(
            `Resolve failed:\n${error.message}`
        );

        console.error(error);
    }
}


// ============================================================
// HELPERS
// ============================================================

function setText(id, value) {

    const element =
        document.getElementById(id);

    if (element) {
        element.textContent =
            value ?? 0;
    }
}


function getRiskClass(risk) {

    if (!risk) {
        return "";
    }

    return `risk-${String(risk).toLowerCase()}`;
}


function formatDate(value) {

    if (!value) {
        return "-";
    }

    try {
        return new Date(value).toLocaleString();
    } catch {
        return value;
    }
}


function escapeHTML(value) {

    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}