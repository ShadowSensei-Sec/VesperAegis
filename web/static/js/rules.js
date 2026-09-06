/* ============================================================
   FIREWALL PROJECT - RULES PAGE
   ============================================================ */

let allRules = [];
let editingRuleId = null;


/* ============================================================
   API
   ============================================================ */

async function fetchRules() {

    const response = await fetch("/api/rules");

    if (!response.ok) {
        throw new Error(
            `Failed to load firewall rules (${response.status})`
        );
    }

    const data = await response.json();

    if (Array.isArray(data)) {
        return data;
    }

    return data.rules || [];
}


async function createRule(ruleData) {

    const response = await fetch("/api/rules", {
        method: "POST",

        headers: {
            "Content-Type": "application/json"
        },

        body: JSON.stringify(ruleData)
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.detail ||
            "Failed to create firewall rule."
        );
    }

    return data;
}


async function updateRule(ruleId, ruleData) {

    const response = await fetch(
        `/api/rules/${ruleId}`,
        {
            method: "PUT",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(ruleData)
        }
    );

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.detail ||
            "Failed to update firewall rule."
        );
    }

    return data;
}


/* ============================================================
   LOAD RULES
   ============================================================ */

async function loadRules() {

    try {

        allRules = await fetchRules();

        updateSummary();
        updateCharts();
        applyFilters();

    } catch (error) {

        console.error(
            "[!] Failed to load firewall rules:",
            error
        );

        const table =
            document.getElementById("rules-table-body");

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="9">

                        <div class="empty-rules">

                            <strong>
                                Unable to load firewall rules
                            </strong>

                            ${escapeHtml(error.message)}

                        </div>

                    </td>
                </tr>
            `;
        }
    }
}


/* ============================================================
   SUMMARY
   ============================================================ */

function updateSummary() {

    const total =
        allRules.length;

    const active =
        allRules.filter(
            rule => Boolean(rule.enabled)
        ).length;

    const disabled =
        total - active;

    const allow =
        allRules.filter(
            rule =>
                String(rule.action).toLowerCase() === "allow"
        ).length;

    const deny =
        allRules.filter(
            rule =>
                String(rule.action).toLowerCase() === "deny"
        ).length;


    setText("total-rules", total);
    setText("active-rules", active);
    setText("disabled-rules", disabled);

    setText("allow-rules", allow);
    setText("deny-rules", deny);

    setText("rule-total-chart", total);
    setText("status-total-chart", total);
}


/* ============================================================
   CHARTS
   ============================================================ */

function updateCharts() {

    const total =
        allRules.length;

    const allow =
        allRules.filter(
            rule =>
                String(rule.action).toLowerCase() === "allow"
        ).length;

    const deny =
        allRules.filter(
            rule =>
                String(rule.action).toLowerCase() === "deny"
        ).length;

    const enabled =
        allRules.filter(
            rule => Boolean(rule.enabled)
        ).length;

    const disabled =
        total - enabled;


    /*
     * Allow / Deny donut
     */

    const allowDegrees =
        total > 0
            ? (allow / total) * 360
            : 0;

    const ruleDonut =
        document.getElementById("rule-donut");

    if (ruleDonut) {

        ruleDonut.style.background =
            `conic-gradient(
                var(--green) 0deg ${allowDegrees}deg,
                var(--red) ${allowDegrees}deg 360deg
            )`;
    }


    /*
     * Enabled / Disabled donut
     */

    const enabledDegrees =
        total > 0
            ? (enabled / total) * 360
            : 0;

    const statusDonut =
        document.getElementById("status-donut");

    if (statusDonut) {

        statusDonut.style.background =
            `conic-gradient(
                var(--blue) 0deg ${enabledDegrees}deg,
                #61738a ${enabledDegrees}deg 360deg
            )`;
    }


    /*
     * Percentages
     */

    const allowPercentage =
        total > 0
            ? Math.round((allow / total) * 100)
            : 0;

    const denyPercentage =
        total > 0
            ? Math.round((deny / total) * 100)
            : 0;

    const enabledPercentage =
        total > 0
            ? Math.round((enabled / total) * 100)
            : 0;

    const disabledPercentage =
        total > 0
            ? Math.round((disabled / total) * 100)
            : 0;


    setText(
        "allow-percentage",
        `${allowPercentage}%`
    );

    setText(
        "deny-percentage",
        `${denyPercentage}%`
    );

    setText(
        "enabled-percentage",
        `${enabledPercentage}%`
    );

    setText(
        "disabled-percentage",
        `${disabledPercentage}%`
    );


    updateProtocolDistribution();
}


/* ============================================================
   PROTOCOL DISTRIBUTION
   ============================================================ */

function updateProtocolDistribution() {

    const container =
        document.getElementById(
            "protocol-distribution"
        );

    if (!container) {
        return;
    }


    const protocols = {
        tcp: 0,
        udp: 0,
        icmp: 0,
        icmpv6: 0,
        any: 0
    };


    allRules.forEach(rule => {

        const protocol =
            String(rule.protocol || "any")
                .toLowerCase();

        if (
            Object.prototype.hasOwnProperty.call(
                protocols,
                protocol
            )
        ) {
            protocols[protocol]++;
        }
    });


    const entries = [
        ["TCP", protocols.tcp],
        ["UDP", protocols.udp],
        ["ICMP", protocols.icmp],
        ["ICMPv6", protocols.icmpv6],
        ["Any", protocols.any]
    ];


    const maximum =
        Math.max(
            ...entries.map(
                item => item[1]
            ),
            1
        );


    container.innerHTML =
        entries.map(
            ([name, count]) => {

                const percentage =
                    (count / maximum) * 100;

                return `
                    <div class="protocol-row">

                        <span class="protocol-name">
                            ${escapeHtml(name)}
                        </span>

                        <div class="protocol-bar">

                            <div
                                class="protocol-bar-fill"
                                style="width: ${percentage}%"
                            ></div>

                        </div>

                        <span class="protocol-value">
                            ${count}
                        </span>

                    </div>
                `;
            }
        ).join("");
}


/* ============================================================
   RENDER RULE TABLE
   ============================================================ */

function renderRules(rules) {

    const table =
        document.getElementById(
            "rules-table-body"
        );

    if (!table) {
        return;
    }


    if (!rules.length) {

        table.innerHTML = `
            <tr>
                <td colspan="9">

                    <div class="empty-rules">

                        <strong>
                            No firewall rules found
                        </strong>

                        Try changing your filters
                        or create a new rule.

                    </div>

                </td>
            </tr>
        `;

        return;
    }


    table.innerHTML =
        rules.map(
            rule => createRuleRow(rule)
        ).join("");
}


/* ============================================================
   CREATE RULE ROW
   ============================================================ */

function createRuleRow(rule) {

    const action =
        String(rule.action || "")
            .toLowerCase();

    const protocol =
        String(rule.protocol || "any")
            .toUpperCase();


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


    const enabled =
        Boolean(rule.enabled);


    const actionClass =
        action === "allow"
            ? "action-allow"
            : "action-deny";


    const actionText =
        action === "allow"
            ? "ALLOW"
            : "DENY";


    const statusClass =
        enabled
            ? "enabled"
            : "disabled";


    const statusText =
        enabled
            ? "Enabled"
            : "Disabled";


    return `
        <tr>

            <td>
                ${escapeHtml(rule.id)}
            </td>

            <td>
                ${escapeHtml(rule.priority ?? 100)}
            </td>

            <td>
                <strong>
                    ${escapeHtml(
                        rule.name || "Unnamed Rule"
                    )}
                </strong>
            </td>

            <td>

                <span
                    class="action-badge ${actionClass}"
                >
                    ${actionText}
                </span>

            </td>

            <td>
                ${escapeHtml(protocol)}
            </td>

            <td>
                ${escapeHtml(source)}
            </td>

            <td>
                ${escapeHtml(destination)}
            </td>

            <td>

                <span
                    class="rule-status ${statusClass}"
                >

                    <span
                        class="rule-status-dot"
                    ></span>

                    ${statusText}

                </span>

            </td>

            <td>

                <div class="rule-actions">

                    <button
                        class="rule-action-btn"
                        title="Edit rule"
                        type="button"
                        onclick="editRule(${Number(rule.id)})"
                    >
                        ✎
                    </button>


                    <button
                        class="rule-action-btn"
                        title="${enabled ? "Disable" : "Enable"} rule"
                        type="button"
                        onclick="toggleRule(${Number(rule.id)})"
                    >
                        ${enabled ? "Ⅱ" : "▶"}
                    </button>


                    <button
                        class="rule-action-btn delete"
                        title="Delete rule"
                        type="button"
                        onclick="deleteRule(${Number(rule.id)})"
                    >
                        ×
                    </button>

                </div>

            </td>

        </tr>
    `;
}


/* ============================================================
   FORMAT ENDPOINT
   ============================================================ */

function formatEndpoint(ip, port) {

    const address =
        ip || "Any";


    if (
        port !== null &&
        port !== undefined &&
        port !== ""
    ) {
        return `${address}:${port}`;
    }


    return address;
}


/* ============================================================
   FILTERING
   ============================================================ */

function applyFilters() {

    const search =
        document.getElementById(
            "rule-search"
        )?.value
            .trim()
            .toLowerCase() || "";


    const action =
        document.getElementById(
            "action-filter"
        )?.value || "all";


    const protocol =
        document.getElementById(
            "protocol-filter"
        )?.value || "all";


    const status =
        document.getElementById(
            "status-filter"
        )?.value || "all";


    const filtered =
        allRules.filter(rule => {

            const ruleText =
                [
                    rule.id,
                    rule.name,
                    rule.action,
                    rule.protocol,
                    rule.source_ip,
                    rule.source_port,
                    rule.destination_ip,
                    rule.destination_port,
                    rule.description,
                    rule.priority
                ]
                    .filter(
                        value =>
                            value !== null &&
                            value !== undefined
                    )
                    .join(" ")
                    .toLowerCase();


            if (
                search &&
                !ruleText.includes(search)
            ) {
                return false;
            }


            if (
                action !== "all" &&
                String(rule.action).toLowerCase()
                    !== action
            ) {
                return false;
            }


            if (
                protocol !== "all" &&
                String(rule.protocol).toLowerCase()
                    !== protocol
            ) {
                return false;
            }


            if (
                status === "enabled" &&
                !Boolean(rule.enabled)
            ) {
                return false;
            }


            if (
                status === "disabled" &&
                Boolean(rule.enabled)
            ) {
                return false;
            }


            return true;
        });


    renderRules(filtered);
}


/* ============================================================
   RESET FILTERS
   ============================================================ */

function resetFilters() {

    const search =
        document.getElementById("rule-search");

    const action =
        document.getElementById("action-filter");

    const protocol =
        document.getElementById("protocol-filter");

    const status =
        document.getElementById("status-filter");


    if (search) {
        search.value = "";
    }

    if (action) {
        action.value = "all";
    }

    if (protocol) {
        protocol.value = "all";
    }

    if (status) {
        status.value = "all";
    }


    renderRules(allRules);
}


/* ============================================================
   TOGGLE RULE
   ============================================================ */

async function toggleRule(ruleId) {

    try {

        const response =
            await fetch(
                `/api/rules/${ruleId}/toggle`,
                {
                    method: "PATCH"
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Failed to toggle rule"
            );
        }


        await loadRules();

    } catch (error) {

        console.error(
            "[!] Toggle rule failed:",
            error
        );

        alert(
            error.message ||
            "Failed to toggle firewall rule."
        );
    }
}


/* ============================================================
   DELETE RULE
   ============================================================ */

async function deleteRule(ruleId) {

    const rule =
        allRules.find(
            item =>
                Number(item.id) === Number(ruleId)
        );


    const ruleName =
        rule?.name ||
        `Rule ${ruleId}`;


    const confirmed =
        window.confirm(
            `Delete "${ruleName}"?\n\nThis will remove the firewall rule from the configuration and nftables.`
        );


    if (!confirmed) {
        return;
    }


    try {

        const response =
            await fetch(
                `/api/rules/${ruleId}`,
                {
                    method: "DELETE"
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Failed to delete rule"
            );
        }


        await loadRules();

    } catch (error) {

        console.error(
            "[!] Delete rule failed:",
            error
        );

        alert(
            error.message ||
            "Failed to delete firewall rule."
        );
    }
}


/* ============================================================
   OPEN ADD MODAL
   ============================================================ */

function openAddRuleModal() {

    editingRuleId = null;


    const form =
        document.getElementById("rule-form");

    if (form) {
        form.reset();
    }


    setText(
        "rule-modal-title",
        "Add Firewall Rule"
    );

    setText(
        "rule-modal-description",
        "Create a new firewall policy"
    );

    setText(
        "save-rule-button",
        "Create Rule"
    );


    const idField =
        document.getElementById("rule-id");

    if (idField) {
        idField.value = "";
    }


    const enabled =
        document.getElementById("rule-enabled");

    if (enabled) {
        enabled.checked = true;
    }


    const priority =
        document.getElementById("rule-priority");

    if (priority) {
        priority.value = "100";
    }


    clearFormError();

    showRuleModal();
}


/* ============================================================
   EDIT RULE
   ============================================================ */

function editRule(ruleId) {

    const rule =
        allRules.find(
            item =>
                Number(item.id) === Number(ruleId)
        );


    if (!rule) {

        alert(
            "The selected firewall rule could not be found."
        );

        return;
    }


    editingRuleId = Number(rule.id);


    setInputValue(
        "rule-id",
        rule.id
    );

    setInputValue(
        "rule-name",
        rule.name || ""
    );

    setInputValue(
        "rule-action",
        String(rule.action || "deny").toLowerCase()
    );

    setInputValue(
        "rule-protocol",
        String(rule.protocol || "any").toLowerCase()
    );

    setInputValue(
        "rule-source-ip",
        rule.source_ip || ""
    );

    setInputValue(
        "rule-source-port",
        rule.source_port ?? ""
    );

    setInputValue(
        "rule-destination-ip",
        rule.destination_ip || ""
    );

    setInputValue(
        "rule-destination-port",
        rule.destination_port ?? ""
    );

    setInputValue(
        "rule-interface",
        rule.interface || ""
    );

    setInputValue(
        "rule-direction",
        rule.direction || ""
    );

    setInputValue(
        "rule-priority",
        rule.priority ?? 100
    );

    setInputValue(
        "rule-description",
        rule.description || ""
    );


    const enabled =
        document.getElementById("rule-enabled");

    if (enabled) {
        enabled.checked =
            Boolean(rule.enabled);
    }


    setText(
        "rule-modal-title",
        "Edit Firewall Rule"
    );

    setText(
        "rule-modal-description",
        `Modify firewall rule ${rule.id}`
    );

    setText(
        "save-rule-button",
        "Update Rule"
    );


    clearFormError();

    showRuleModal();
}


/* ============================================================
   SAVE RULE
   ============================================================ */

async function saveRule(event) {

    event.preventDefault();


    clearFormError();


    const ruleData =
        collectRuleFormData();


    const validationError =
        validateRuleForm(ruleData);


    if (validationError) {

        showFormError(
            validationError
        );

        return;
    }


    const saveButton =
        document.getElementById(
            "save-rule-button"
        );


    const originalText =
        editingRuleId
            ? "Update Rule"
            : "Create Rule";


    try {

        if (saveButton) {

            saveButton.disabled = true;

            saveButton.textContent =
                editingRuleId
                    ? "Updating..."
                    : "Creating...";
        }


        if (editingRuleId !== null) {

            await updateRule(
                editingRuleId,
                ruleData
            );

        } else {

            await createRule(
                ruleData
            );
        }


        closeRuleModal();

        await loadRules();


    } catch (error) {

        console.error(
            "[!] Save rule failed:",
            error
        );

        showFormError(
            error.message ||
            "Failed to save firewall rule."
        );

    } finally {

        if (saveButton) {

            saveButton.disabled = false;

            saveButton.textContent =
                originalText;
        }
    }
}


/* ============================================================
   COLLECT FORM DATA
   ============================================================ */

function collectRuleFormData() {

    const sourcePort =
        document.getElementById(
            "rule-source-port"
        )?.value.trim();


    const destinationPort =
        document.getElementById(
            "rule-destination-port"
        )?.value.trim();


    const direction =
        document.getElementById(
            "rule-direction"
        )?.value.trim();


    return {

        name:
            document.getElementById(
                "rule-name"
            )?.value.trim() || "",


        action:
            document.getElementById(
                "rule-action"
            )?.value || "deny",


        protocol:
            document.getElementById(
                "rule-protocol"
            )?.value || "any",


        source_ip:
            emptyToNull(
                document.getElementById(
                    "rule-source-ip"
                )?.value.trim()
            ),


        source_port:
            sourcePort
                ? Number(sourcePort)
                : null,


        destination_ip:
            emptyToNull(
                document.getElementById(
                    "rule-destination-ip"
                )?.value.trim()
            ),


        destination_port:
            destinationPort
                ? Number(destinationPort)
                : null,


        interface:
            emptyToNull(
                document.getElementById(
                    "rule-interface"
                )?.value.trim()
            ),


        direction:
            direction
                ? direction
                : null,


        enabled:
            Boolean(
                document.getElementById(
                    "rule-enabled"
                )?.checked
            ),


        description:
            document.getElementById(
                "rule-description"
            )?.value.trim() || "",


        priority:
            Number(
                document.getElementById(
                    "rule-priority"
                )?.value || 100
            )
    };
}


/* ============================================================
   FORM VALIDATION
   ============================================================ */

function validateRuleForm(rule) {

    if (!rule.name) {
        return "Rule name is required.";
    }


    if (!rule.action) {
        return "Action is required.";
    }


    if (!rule.protocol) {
        return "Protocol is required.";
    }


    if (
        rule.source_port !== null &&
        (
            !Number.isInteger(rule.source_port) ||
            rule.source_port < 1 ||
            rule.source_port > 65535
        )
    ) {
        return "Source port must be between 1 and 65535.";
    }


    if (
        rule.destination_port !== null &&
        (
            !Number.isInteger(rule.destination_port) ||
            rule.destination_port < 1 ||
            rule.destination_port > 65535
        )
    ) {
        return "Destination port must be between 1 and 65535.";
    }


    if (
        rule.protocol !== "tcp" &&
        rule.protocol !== "udp"
    ) {

        if (
            rule.source_port !== null ||
            rule.destination_port !== null
        ) {
            return "Ports can only be used with TCP or UDP.";
        }
    }


    if (
        !Number.isInteger(rule.priority) ||
        rule.priority < 1 ||
        rule.priority > 10000
    ) {
        return "Priority must be between 1 and 10000.";
    }


    return null;
}


/* ============================================================
   MODAL CONTROLS
   ============================================================ */

function showRuleModal() {

    const modal =
        document.getElementById(
            "rule-modal"
        );

    if (!modal) {
        return;
    }


    modal.classList.add("open");

    modal.setAttribute(
        "aria-hidden",
        "false"
    );


    document.body.style.overflow =
        "hidden";


    const nameInput =
        document.getElementById(
            "rule-name"
        );

    if (nameInput) {

        setTimeout(
            () => nameInput.focus(),
            50
        );
    }
}


function closeRuleModal() {

    const modal =
        document.getElementById(
            "rule-modal"
        );

    if (!modal) {
        return;
    }


    modal.classList.remove("open");

    modal.setAttribute(
        "aria-hidden",
        "true"
    );


    document.body.style.overflow =
        "";


    editingRuleId = null;

    clearFormError();
}


/* ============================================================
   FORM ERROR
   ============================================================ */

function showFormError(message) {

    const errorBox =
        document.getElementById(
            "rule-form-error"
        );

    if (!errorBox) {
        return;
    }


    errorBox.textContent =
        message;


    errorBox.hidden =
        false;
}


function clearFormError() {

    const errorBox =
        document.getElementById(
            "rule-form-error"
        );

    if (!errorBox) {
        return;
    }


    errorBox.textContent =
        "";

    errorBox.hidden =
        true;
}


/* ============================================================
   INPUT HELPERS
   ============================================================ */

function setInputValue(id, value) {

    const element =
        document.getElementById(id);

    if (element) {
        element.value =
            value ?? "";
    }
}


function emptyToNull(value) {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return null;
    }

    return value;
}


/* ============================================================
   DOM READY
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    () => {


        /*
         * Add Rule
         */

        const addButton =
            document.getElementById(
                "add-rule-button"
            );

        if (addButton) {

            addButton.addEventListener(
                "click",
                openAddRuleModal
            );
        }


        /*
         * Save Rule
         */

        const form =
            document.getElementById(
                "rule-form"
            );

        if (form) {

            form.addEventListener(
                "submit",
                saveRule
            );
        }


        /*
         * Close button
         */

        const closeButton =
            document.getElementById(
                "close-rule-modal"
            );

        if (closeButton) {

            closeButton.addEventListener(
                "click",
                closeRuleModal
            );
        }


        /*
         * Cancel button
         */

        const cancelButton =
            document.getElementById(
                "cancel-rule-button"
            );

        if (cancelButton) {

            cancelButton.addEventListener(
                "click",
                closeRuleModal
            );
        }


        /*
         * Modal backdrop
         */

        const backdrop =
            document.getElementById(
                "rule-modal-backdrop"
            );

        if (backdrop) {

            backdrop.addEventListener(
                "click",
                closeRuleModal
            );
        }


        /*
         * Escape key
         */

        document.addEventListener(
            "keydown",
            event => {

                if (
                    event.key === "Escape"
                ) {

                    const modal =
                        document.getElementById(
                            "rule-modal"
                        );

                    if (
                        modal &&
                        modal.classList.contains("open")
                    ) {
                        closeRuleModal();
                    }
                }
            }
        );


        /*
         * Search
         */

        const search =
            document.getElementById(
                "rule-search"
            );

        if (search) {

            search.addEventListener(
                "input",
                applyFilters
            );
        }


        /*
         * Dropdown filters
         */

        [
            "action-filter",
            "protocol-filter",
            "status-filter"
        ].forEach(id => {

            const element =
                document.getElementById(id);

            if (element) {

                element.addEventListener(
                    "change",
                    applyFilters
                );
            }
        });


        /*
         * Reset
         */

        const reset =
            document.getElementById(
                "reset-filters"
            );

        if (reset) {

            reset.addEventListener(
                "click",
                resetFilters
            );
        }


        /*
         * Initial load
         */

        loadRules();
    }
);


/* ============================================================
   UTILITIES
   ============================================================ */

function setText(id, value) {

    const element =
        document.getElementById(id);

    if (element) {
        element.textContent =
            value;
    }
}


function escapeHtml(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }


    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}