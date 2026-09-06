function formatBytes(bytes) {
    if (!bytes || bytes <= 0) {
        return "0 B";
    }

    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = bytes;
    let index = 0;

    while (value >= 1024 && index < units.length - 1) {
        value /= 1024;
        index++;
    }

    return `${value.toFixed(1)} ${units[index]}`;
}


function formatUptime(seconds) {
    if (!seconds || seconds <= 0) {
        return "0 seconds";
    }

    const days = Math.floor(seconds / 86400);
    seconds %= 86400;

    const hours = Math.floor(seconds / 3600);
    seconds %= 3600;

    const minutes = Math.floor(seconds / 60);

    const parts = [];

    if (days > 0) {
        parts.push(`${days} day${days !== 1 ? "s" : ""}`);
    }

    if (hours > 0) {
        parts.push(`${hours} hour${hours !== 1 ? "s" : ""}`);
    }

    if (minutes > 0) {
        parts.push(`${minutes} min`);
    }

    if (!parts.length) {
        return "Less than 1 min";
    }

    return parts.join(" ");
}


function escapeHtml(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function updateElement(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}


function renderSystemInfo(data) {

    updateElement(
        "hostname",
        data.hostname || "Unavailable"
    );

    updateElement(
        "operating-system",
        data.operating_system || "Unavailable"
    );

    updateElement(
        "os-release",
        data.os_release || "Unavailable"
    );

    updateElement(
        "kernel",
        data.kernel || "Unavailable"
    );

    updateElement(
        "architecture",
        data.architecture || "Unavailable"
    );

    updateElement(
        "processor",
        data.processor || "Unavailable"
    );

    if (data.cpu) {

        updateElement(
            "cpu-usage",
            `${data.cpu.usage_percent ?? 0}%`
        );

        updateElement(
            "logical-cores",
            data.cpu.logical_cores ?? "Unavailable"
        );

        updateElement(
            "physical-cores",
            data.cpu.physical_cores ?? "Unavailable"
        );

        const cpuProgress =
            document.getElementById("cpu-progress");

        if (cpuProgress) {
            cpuProgress.style.width =
                `${Math.min(data.cpu.usage_percent ?? 0, 100)}%`;
        }
    }


    if (data.memory) {

        updateElement(
            "memory-usage",
            `${data.memory.usage_percent ?? 0}%`
        );

        const memoryProgress =
            document.getElementById("memory-progress");

        if (memoryProgress) {
            memoryProgress.style.width =
                `${Math.min(data.memory.usage_percent ?? 0, 100)}%`;
        }
    }


    if (data.disk) {

        updateElement(
            "disk-usage",
            `${data.disk.usage_percent ?? 0}%`
        );

        const diskProgress =
            document.getElementById("disk-progress");

        if (diskProgress) {
            diskProgress.style.width =
                `${Math.min(data.disk.usage_percent ?? 0, 100)}%`;
        }
    }


    if (data.uptime) {

        updateElement(
            "uptime",
            formatUptime(data.uptime.seconds)
        );
    }


    updateElement(
        "firewall-status",
        data.services?.firewall_application?.status === "running"
            ? "Running"
            : "Unavailable"
    );
}


function renderNetworkInterfaces(interfaces) {

    const container =
        document.getElementById("network-interfaces");

    if (!container) {
        return;
    }

    if (!interfaces || !interfaces.length) {

        container.innerHTML = `
            <tr>
                <td colspan="9" class="empty-state">
                    No network interfaces detected.
                </td>
            </tr>
        `;

        return;
    }

    container.innerHTML = interfaces.map(interfaceData => {

        const ipv4 =
            interfaceData.ipv4_addresses?.length
                ? interfaceData.ipv4_addresses.join(", ")
                : "—";

        const ipv6 =
            interfaceData.ipv6_addresses?.length
                ? interfaceData.ipv6_addresses.join(", ")
                : "—";

        const status =
            interfaceData.status === "UP"
                ? "up"
                : "down";

        return `
            <tr>
                <td>
                    <strong>
                        ${escapeHtml(interfaceData.name)}
                    </strong>
                </td>

                <td>
                    <span class="interface-status ${status}">
                        ${escapeHtml(interfaceData.status)}
                    </span>
                </td>

                <td>${escapeHtml(ipv4)}</td>

                <td>${escapeHtml(ipv6)}</td>

                <td>
                    ${escapeHtml(
                        interfaceData.mac_address || "—"
                    )}
                </td>

                <td>
                    ${Number(
                        interfaceData.rx_packets || 0
                    ).toLocaleString()}
                </td>

                <td>
                    ${Number(
                        interfaceData.tx_packets || 0
                    ).toLocaleString()}
                </td>

                <td>
                    ${formatBytes(
                        interfaceData.rx_bytes || 0
                    )}
                </td>

                <td>
                    ${formatBytes(
                        interfaceData.tx_bytes || 0
                    )}
                </td>
            </tr>
        `;

    }).join("");
}


function formatServiceName(name) {

    const names = {
        firewall_application: "Firewall Application",
        nftables: "nftables",
        database: "Database",
        packet_monitoring: "Packet Monitoring",
        rest_api: "REST API",
        web_interface: "Web Interface"
    };

    return names[name] || name;
}


function renderServices(services) {

    const container =
        document.getElementById("firewall-services");

    if (!container) {
        return;
    }

    if (!services) {
        container.innerHTML = `
            <div class="empty-state">
                Service information unavailable.
            </div>
        `;

        return;
    }

    container.innerHTML = Object.entries(services)
        .map(([name, service]) => {

            const status =
                service.status || "unknown";

            const operational =
                ["running", "active", "connected", "available"]
                    .includes(status);

            return `
                <div class="service-card">

                    <div class="service-name">
                        ${escapeHtml(
                            formatServiceName(name)
                        )}
                    </div>

                    <div class="service-status ${
                        operational ? "operational" : "error"
                    }">

                        <span class="status-dot"></span>

                        ${escapeHtml(status)}

                    </div>

                </div>
            `;

        })
        .join("");
}


function renderConfiguration(configuration) {

    if (!configuration) {
        return;
    }

    const policies =
        configuration.default_policy || {};

    const rules =
        configuration.rules || {};


    updateElement(
        "input-policy",
        policies.input
            ? policies.input.toUpperCase()
            : "Unavailable"
    );

    updateElement(
        "output-policy",
        policies.output
            ? policies.output.toUpperCase()
            : "Unavailable"
    );

    updateElement(
        "forward-policy",
        policies.forward
            ? policies.forward.toUpperCase()
            : "Unavailable"
    );

    updateElement(
        "active-rules",
        rules.active_rules ?? 0
    );

    updateElement(
        "disabled-rules",
        rules.disabled_rules ?? 0
    );

    updateElement(
        "total-rules",
        rules.total_rules ?? 0
    );
}


async function loadSystemInfo() {

    try {

        const response = await fetch(
            "/api/system",
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }

        const data =
            await response.json();

        renderSystemInfo(data);

        renderNetworkInterfaces(
            data.network_interfaces || []
        );

        renderServices(
            data.services || {}
        );

        renderConfiguration(
            data.configuration || {}
        );


        const updated =
            document.getElementById("last-updated");

        if (updated) {

            updated.textContent =
                `Last updated: ${new Date().toLocaleTimeString()}`;
        }

    } catch (error) {

        console.error(
            "Failed to load system information:",
            error
        );

        const message =
            document.getElementById("system-message");

        if (message) {

            message.hidden = false;

            message.textContent =
                "Unable to load system information.";
        }
    }
}


/* ========================================================= */
/* REFRESH */
/* ========================================================= */

const refreshSystem =
    document.getElementById("refresh-system");

const refreshOperation =
    document.getElementById("refresh-operation");


if (refreshSystem) {

    refreshSystem.addEventListener(
        "click",
        loadSystemInfo
    );
}


if (refreshOperation) {

    refreshOperation.addEventListener(
        "click",
        loadSystemInfo
    );
}


/* ========================================================= */
/* INITIAL LOAD */
/* ========================================================= */

loadSystemInfo();


/* ========================================================= */
/* LIVE UPDATE */
/* ========================================================= */

setInterval(
    loadSystemInfo,
    5000
);