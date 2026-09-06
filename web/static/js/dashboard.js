// ============================================================
// FIREWALL DASHBOARD
// ============================================================

let selectedRange = "1h";


// ============================================================
// HELPERS
// ============================================================

function formatBytes(bytes) {
    bytes = Number(bytes) || 0;

    if (bytes < 1024) {
        return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    if (bytes < 1024 * 1024 * 1024) {
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }

    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}


function formatTime(timestamp) {
    if (!timestamp) {
        return "-";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleTimeString();
}


function formatEndpoint(ip, port) {
    if (!ip) {
        return "Any";
    }

    if (port !== null && port !== undefined) {
        return `${ip}:${port}`;
    }

    return ip;
}


// ============================================================
// FIREWALL STATUS
// ============================================================

async function loadStatus() {

    const statusElement =
        document.getElementById("status");

    const firewallStatus =
        document.getElementById("firewall-status");

    try {

        const response =
            await fetch("/api/status");

        if (!response.ok) {
            throw new Error("Status request failed");
        }

        const data =
            await response.json();

        statusElement.textContent =
            "Online";

        statusElement.classList.remove("offline");

        if (firewallStatus) {
            firewallStatus.textContent =
                data.status || "running";
        }

    } catch (error) {

        console.error(
            "[!] Failed to load firewall status:",
            error
        );

        statusElement.textContent =
            "Offline";

        statusElement.classList.add("offline");

        if (firewallStatus) {
            firewallStatus.textContent =
                "offline";
        }
    }
}


// ============================================================
// RULES
// ============================================================

async function loadRules() {

    const table =
        document.getElementById("rules-table");

    try {

        const response =
            await fetch("/api/rules");

        if (!response.ok) {
            throw new Error("Rules request failed");
        }

        const data =
            await response.json();

        const rules =
            data.rules || [];

        const activeRules =
            rules.filter(rule => rule.enabled);

        table.innerHTML = "";

        if (activeRules.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        No active firewall rules.
                    </td>
                </tr>
            `;

            return;
        }

        // Show only a small dashboard preview.
        const previewRules =
            activeRules.slice(0, 5);

        previewRules.forEach(rule => {

            const row =
                document.createElement("tr");

            const source =
                formatEndpoint(
                    rule.source_ip,
                    rule.source_port
                );

            const destination =
                formatEndpoint(
                    rule.destination_ip,
                    rule.destination_port
                );

            const actionClass =
                rule.action === "allow"
                    ? "action-allow"
                    : "action-deny";

            row.innerHTML = `
                <td>${rule.name || "-"}</td>

                <td class="${actionClass}">
                    ${(rule.action || "-").toUpperCase()}
                </td>

                <td>
                    ${(rule.protocol || "any").toUpperCase()}
                </td>

                <td>${source}</td>

                <td>${destination}</td>

                <td class="rule-enabled">
                    Enabled
                </td>
            `;

            table.appendChild(row);
        });

    } catch (error) {

        console.error(
            "[!] Failed to load rules:",
            error
        );

        table.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    Failed to load firewall rules.
                </td>
            </tr>
        `;
    }
}


// ============================================================
// STATISTICS
// ============================================================

async function loadStatistics() {

    try {

        const response =
            await fetch(
                `/api/statistics?range=${selectedRange}`
            );

        if (!response.ok) {
            throw new Error(
                "Statistics request failed"
            );
        }

        const stats =
            await response.json();


        // ================================================
        // SUMMARY
        // ================================================

        document
            .getElementById("packet-count")
            .textContent =
            Number(stats.total_packets || 0)
                .toLocaleString();


        document
            .getElementById("accepted-count")
            .textContent =
            Number(stats.accepted_packets || 0)
                .toLocaleString();


        document
            .getElementById("dropped-count")
            .textContent =
            Number(stats.dropped_packets || 0)
                .toLocaleString();


        document
            .getElementById("byte-count")
            .textContent =
            formatBytes(stats.total_bytes);


        // ================================================
        // PROTOCOL DISTRIBUTION
        // ================================================

        renderProtocols(
            stats.protocols || {}
        );


        // ================================================
        // TRAFFIC OVERVIEW
        // ================================================

        renderTrafficOverview(
            stats.time_statistics || {}
        );

    } catch (error) {

        console.error(
            "[!] Failed to load statistics:",
            error
        );

        document
            .getElementById("packet-count")
            .textContent = "0";

        document
            .getElementById("accepted-count")
            .textContent = "0";

        document
            .getElementById("dropped-count")
            .textContent = "0";

        document
            .getElementById("byte-count")
            .textContent = "0 B";

        renderProtocols({});

        renderTrafficOverview({});
    }
}


// ============================================================
// PROTOCOL DISTRIBUTION
// ============================================================

function renderProtocols(protocols) {

    const container =
        document.getElementById(
            "protocol-distribution"
        );

    container.innerHTML = "";

    const entries =
        Object.entries(protocols)
            .filter(
                ([, data]) =>
                    Number(data.packets || 0) > 0
            )
            .sort(
                (a, b) =>
                    Number(b[1].packets || 0) -
                    Number(a[1].packets || 0)
            );

    if (entries.length === 0) {

        container.innerHTML = `
            <div class="empty-state">
                No protocol data available.
            </div>
        `;

        return;
    }

    entries.forEach(
        ([protocol, data]) => {

            const item =
                document.createElement("div");

            item.className =
                "protocol-item";

            item.innerHTML = `
                <span class="protocol-name">
                    ${protocol.toUpperCase()}
                </span>

                <span class="protocol-value">
                    ${Number(data.packets || 0).toLocaleString()}
                    packets ·
                    ${formatBytes(data.bytes)}
                </span>
            `;

            container.appendChild(item);
        }
    );
}


// ============================================================
// TRAFFIC OVERVIEW
// ============================================================

function renderTrafficOverview(timeStatistics) {

    const chart =
        document.getElementById(
            "traffic-chart"
        );

    if (!chart) {
        return;
    }

    chart.innerHTML = "";


    const entries =
        Object.entries(timeStatistics || {})
            .sort(
                (a, b) =>
                    a[0].localeCompare(b[0])
            );


    // ---------------------------------------------------------
    // NO DATA
    // ---------------------------------------------------------

    if (entries.length === 0) {

        chart.innerHTML = `
            <div class="traffic-empty">
                <div class="traffic-empty-title">
                    No traffic data available
                </div>

                <div class="traffic-empty-text">
                    Traffic activity will appear here
                    when firewall events are recorded.
                </div>
            </div>
        `;

        return;
    }


    // ---------------------------------------------------------
    // FIND MAXIMUM PACKET COUNT
    // ---------------------------------------------------------

    const maximumPackets =
        Math.max(
            ...entries.map(
                ([, data]) =>
                    Number(
                        data.packets || 0
                    )
            ),
            1
        );


    // ---------------------------------------------------------
    // CHART
    // ---------------------------------------------------------

    const chartWrapper =
        document.createElement("div");

    chartWrapper.className =
        "traffic-chart-wrapper";


    const chartArea =
        document.createElement("div");

    chartArea.className =
        "traffic-bars";


    // ---------------------------------------------------------
    // SHOW LAST 12 TIME PERIODS
    // ---------------------------------------------------------

    entries
        .slice(-12)
        .forEach(
            ([time, data]) => {

                const packets =
                    Number(
                        data.packets || 0
                    );

                const bytes =
                    Number(
                        data.bytes || 0
                    );

                const allowed =
                    Number(
                        data.allowed_packets || 0
                    );

                const dropped =
                    Number(
                        data.dropped_packets || 0
                    );


                const percentage =
                    Math.max(
                        2,
                        (packets /
                            maximumPackets) *
                            100
                    );


                const barGroup =
                    document.createElement(
                        "div"
                    );

                barGroup.className =
                    "traffic-bar-group";


                const bar =
                    document.createElement(
                        "div"
                    );

                bar.className =
                    "traffic-bar";


                bar.style.height =
                    `${percentage}%`;


                bar.title =
                    `${time} | ` +
                    `${packets.toLocaleString()} packets | ` +
                    `${formatBytes(bytes)}`;


                const label =
                    document.createElement(
                        "div"
                    );

                label.className =
                    "traffic-bar-label";


                label.textContent =
                    time.slice(11);


                const value =
                    document.createElement(
                        "div"
                    );

                value.className =
                    "traffic-bar-value";


                value.textContent =
                    packets.toLocaleString();


                barGroup.appendChild(
                    value
                );

                barGroup.appendChild(
                    bar
                );

                barGroup.appendChild(
                    label
                );


                chartArea.appendChild(
                    barGroup
                );


                // Store details for tooltip/debugging
                bar.dataset.packets =
                    packets;

                bar.dataset.bytes =
                    bytes;

                bar.dataset.allowed =
                    allowed;

                bar.dataset.dropped =
                    dropped;
            }
        );


    chartWrapper.appendChild(
        chartArea
    );


    // ---------------------------------------------------------
    // LEGEND
    // ---------------------------------------------------------

    const legend =
        document.createElement("div");

    legend.className =
        "traffic-chart-legend";


    legend.innerHTML = `
        <span>
            Packets per hour
        </span>

        <span>
            ${entries.length}
            recorded periods
        </span>
    `;


    chartWrapper.appendChild(
        legend
    );


    chart.appendChild(
        chartWrapper
    );
}

// ============================================================
// RECENT SECURITY EVENTS
// ============================================================

async function loadRecentEvents() {

    const table =
        document.getElementById(
            "events-table"
        );

    try {

        const response =
            await fetch("/api/logs?limit=5");

        if (!response.ok) {
            throw new Error(
                "Logs request failed"
            );
        }

        const data =
            await response.json();

        const events =
            data.events || [];

        table.innerHTML = "";

        if (events.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        No security events recorded.
                    </td>
                </tr>
            `;

            return;
        }

        events.slice(0, 5).forEach(
            event => {

                const row =
                    document.createElement("tr");

                const action =
                    event.action || "unknown";

                const actionClass =
                    action === "allow"
                        ? "action-allow"
                        : action === "deny" ||
                          action === "drop"
                            ? "action-deny"
                            : "";

                row.innerHTML = `
                    <td>
                        ${formatTime(event.timestamp)}
                    </td>

                    <td class="${actionClass}">
                        ${action.toUpperCase()}
                    </td>

                    <td>
                        ${(event.protocol || "-").toUpperCase()}
                    </td>

                    <td>
                        ${formatEndpoint(
                            event.source_ip,
                            event.source_port
                        )}
                    </td>

                    <td>
                        ${formatEndpoint(
                            event.destination_ip,
                            event.destination_port
                        )}
                    </td>

                    <td>
                        ${event.rule_name || "-"}
                    </td>
                `;

                table.appendChild(row);
            }
        );

    } catch (error) {

        console.error(
            "[!] Failed to load security events:",
            error
        );

        table.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    Failed to load security events.
                </td>
            </tr>
        `;
    }
}


// ============================================================
// LOAD DASHBOARD
// ============================================================

async function loadDashboard() {

    await Promise.all([
        loadStatus(),
        loadRules(),
        loadStatistics(),
        loadRecentEvents()
    ]);

    const updated =
        document.getElementById(
            "last-updated"
        );

    if (updated) {

        updated.textContent =
            `Last updated: ${
                new Date().toLocaleTimeString()
            }`;
    }
}


// ============================================================
// REFRESH BUTTON
// ============================================================

const refreshButton =
    document.getElementById(
        "refresh-button"
    );

if (refreshButton) {

    refreshButton.addEventListener(
        "click",
        async function() {

            refreshButton.disabled = true;

            refreshButton.textContent =
                "Refreshing...";

            await loadDashboard();

            refreshButton.disabled = false;

            refreshButton.textContent =
                "Refresh";
        }
    );
}


// ============================================================
// TIME RANGE
// ============================================================

const rangeButtons =
    document.querySelectorAll(
        ".time-range-button"
    );

rangeButtons.forEach(
    button => {

        button.addEventListener(
            "click",
            async function() {

                rangeButtons.forEach(
                    item =>
                        item.classList.remove(
                            "active"
                        )
                );

                this.classList.add("active");

                selectedRange =
                    this.dataset.range;

                await loadStatistics();

                const updated =
                    document.getElementById(
                        "last-updated"
                    );

                if (updated) {

                    updated.textContent =
                        `Last updated: ${
                            new Date().toLocaleTimeString()
                        }`;
                }
            }
        );
    }
);


// ============================================================
// VIEW ALL BUTTONS
// ============================================================

const viewAllRules =
    document.getElementById(
        "view-all-rules"
    );

if (viewAllRules) {

    viewAllRules.addEventListener(
        "click",
        function() {

            /*
             * Rules page will be implemented next.
             */
            window.location.href =
                "/rules";
        }
    );
}


const viewAllLogs =
    document.getElementById(
        "view-all-logs"
    );

if (viewAllLogs) {

    viewAllLogs.addEventListener(
        "click",
        function() {

            /*
             * Logs page will be implemented
             * after the dashboard.
             */
            window.location.href =
                "/logs";
        }
    );
}


// ============================================================
// INITIAL LOAD
// ============================================================

loadDashboard();