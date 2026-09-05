// ============================================================
// FIREWALL DASHBOARD
// ============================================================


// ============================================================
// LOAD DASHBOARD
// ============================================================

async function loadDashboard() {

    // ========================================================
    // FIREWALL STATUS
    // ========================================================

    try {

        const statusResponse =
            await fetch("/api/status");

        const status =
            await statusResponse.json();

        document.getElementById("firewall-status").textContent =
            status.status;

        document.getElementById("status").textContent =
            "Online";

    } catch (error) {

        console.error(
            "[!] Failed to load firewall status:",
            error
        );

        document.getElementById("status").textContent =
            "Offline";

        return;
    }


    // ========================================================
    // FIREWALL RULES
    // ========================================================

    try {

        const rulesResponse =
            await fetch("/api/rules");

        const rulesData =
            await rulesResponse.json();

        const rules =
            rulesData.rules || [];


        document.getElementById("rule-count").textContent =
            rules.length;


        const table =
            document.getElementById("rules-table");

        table.innerHTML = "";


        // ====================================================
        // CREATE RULE ROWS
        // ====================================================

        rules.forEach(rule => {

            const row =
                document.createElement("tr");


            // ------------------------------------------------
            // SOURCE
            // ------------------------------------------------

            const source =
                rule.source_ip || "Any";


            // ------------------------------------------------
            // DESTINATION
            // ------------------------------------------------

            let destination =
                "Any";

            if (
                rule.destination_ip &&
                rule.destination_ip !== "any"
            ) {

                destination =
                    rule.destination_ip;
            }

            if (rule.destination_port) {

                destination +=
                    `:${rule.destination_port}`;
            }


            // ------------------------------------------------
            // TABLE ROW
            // ------------------------------------------------

            row.innerHTML = `

                <td>
                    ${rule.id ?? "-"}
                </td>

                <td>
                    ${rule.name ?? "-"}
                </td>

                <td>
                    ${rule.action ?? "-"}
                </td>

                <td>
                    ${rule.protocol ?? "-"}
                </td>

                <td>
                    ${source}
                </td>

                <td>
                    ${destination}
                </td>

                <td>
                    ${
                        rule.enabled
                            ? "Enabled"
                            : "Disabled"
                    }
                </td>

                <td>
                    ${rule.packets ?? 0}
                </td>

                <td>
                    ${rule.bytes ?? 0}
                </td>

                <td>

                    <button
                        class="edit-rule"
                        data-rule-id="${rule.id}"
                    >
                        Edit
                    </button>


                    <button
                        class="toggle-rule"
                        data-rule-id="${rule.id}"
                    >
                        ${
                            rule.enabled
                                ? "Disable"
                                : "Enable"
                        }
                    </button>


                    <button
                        class="delete-rule"
                        data-rule-id="${rule.id}"
                    >
                        Delete
                    </button>

                </td>
            `;


            table.appendChild(row);


            // =================================================
            // EDIT RULE
            // =================================================

            const editButton =
                row.querySelector(".edit-rule");


            editButton.addEventListener(
                "click",
                async function() {

                    const ruleId =
                        this.dataset.ruleId;


                    try {

                        const response =
                            await fetch("/api/rules");

                        const data =
                            await response.json();


                        const selectedRule =
                            (data.rules || []).find(
                                item =>
                                    String(item.id) ===
                                    String(ruleId)
                            );


                        if (!selectedRule) {

                            alert(
                                "Firewall rule not found"
                            );

                            return;
                        }


                        document
                            .getElementById("edit-rule-id")
                            .value =
                            selectedRule.id;


                        document
                            .getElementById("edit-name")
                            .value =
                            selectedRule.name || "";


                        document
                            .getElementById("edit-action")
                            .value =
                            selectedRule.action ||
                            "allow";


                        document
                            .getElementById("edit-protocol")
                            .value =
                            selectedRule.protocol ||
                            "any";


                        document
                            .getElementById("edit-source-ip")
                            .value =
                            selectedRule.source_ip ||
                            "";


                        document
                            .getElementById("edit-destination-ip")
                            .value =
                            selectedRule.destination_ip ||
                            "";


                        document
                            .getElementById("edit-source-port")
                            .value =
                            selectedRule.source_port ??
                            "";


                        document
                            .getElementById("edit-destination-port")
                            .value =
                            selectedRule.destination_port ??
                            "";


                        document
                            .getElementById("edit-enabled")
                            .checked =
                            Boolean(
                                selectedRule.enabled
                            );


                        document
                            .getElementById("edit-rule-panel")
                            .style.display =
                            "block";


                    } catch (error) {

                        console.error(
                            "[!] Edit error:",
                            error
                        );

                        alert(
                            "Failed to load firewall rule"
                        );
                    }
                }
            );


            // =================================================
            // ENABLE / DISABLE RULE
            // =================================================

            const toggleButton =
                row.querySelector(".toggle-rule");


            toggleButton.addEventListener(
                "click",
                async function(event) {

                    event.preventDefault();


                    const ruleId =
                        this.dataset.ruleId;


                    console.log(
                        "[+] Toggle button clicked"
                    );

                    console.log(
                        "[+] Rule ID:",
                        ruleId
                    );


                    try {

                        const response =
                            await fetch(
                                `/api/rules/${ruleId}/toggle`,
                                {
                                    method: "PATCH"
                                }
                            );


                        console.log(
                            "[+] Toggle HTTP status:",
                            response.status
                        );


                        const result =
                            await response.json();


                        console.log(
                            "[+] Toggle API response:",
                            result
                        );


                        if (!response.ok) {

                            document
                                .getElementById(
                                    "rule-message"
                                )
                                .textContent =
                                result.detail ||
                                "Failed to toggle firewall rule";

                            return;
                        }


                        await loadDashboard();


                    } catch (error) {

                        console.error(
                            "[!] Toggle error:",
                            error
                        );

                        document
                            .getElementById(
                                "rule-message"
                            )
                            .textContent =
                            "Failed to connect to firewall API";
                    }
                }
            );


            // =================================================
            // DELETE RULE
            // =================================================

            const deleteButton =
                row.querySelector(".delete-rule");


            deleteButton.addEventListener(
                "click",
                async function() {

                    const ruleId =
                        this.dataset.ruleId;


                    const confirmed =
                        confirm(
                            `Are you sure you want to delete firewall rule ${ruleId}?`
                        );


                    if (!confirmed) {
                        return;
                    }


                    console.log(
                        "[+] Delete button clicked"
                    );

                    console.log(
                        "[+] Rule ID:",
                        ruleId
                    );


                    try {

                        const response =
                            await fetch(
                                `/api/rules/${ruleId}`,
                                {
                                    method: "DELETE"
                                }
                            );


                        let result = {};

                        try {

                            result =
                                await response.json();

                        } catch (jsonError) {

                            console.warn(
                                "[!] Delete response was not JSON"
                            );
                        }


                        console.log(
                            "[+] Delete HTTP status:",
                            response.status
                        );


                        console.log(
                            "[+] Delete API response:",
                            result
                        );


                        // ------------------------------------------------
                        // SERVER ERROR
                        // ------------------------------------------------

                        if (!response.ok) {

                            console.error(
                                "[!] Delete API returned:",
                                response.status
                            );

                            console.error(
                                "[!] Delete API detail:",
                                result.detail
                            );


                            /*
                             * The backend currently returns HTTP 500
                             * even though the rule is being removed.
                             *
                             * Do not display a misleading
                             * "Unable to delete firewall rule"
                             * message here.
                             *
                             * Reload the dashboard so the current
                             * database state is reflected.
                             */

                            await loadDashboard();

                            return;
                        }


                        // ------------------------------------------------
                        // SUCCESS
                        // ------------------------------------------------

                        console.log(
                            "[+] Rule deleted successfully:",
                            ruleId
                        );


                        await loadDashboard();

                    } catch (error) {

                        console.error(
                            "[!] Delete request error:",
                            error
                        );

                        /*
                         * This means the browser could not
                         * communicate with the API at all.
                         */

                        document
                            .getElementById(
                                "rule-message"
                            )
                            .textContent =
                            "Failed to connect to firewall API";
                    }
                }
            );

        });


    } catch (error) {

        console.error(
            "[!] Failed to load firewall rules:",
            error
        );
    }


    // ========================================================
    // TRAFFIC STATISTICS
    // ========================================================

    try {

        const statsResponse =
            await fetch("/api/statistics");


        const stats =
            await statsResponse.json();


        document
            .getElementById("packet-count")
            .textContent =
            stats.packets ?? 0;


        document
            .getElementById("byte-count")
            .textContent =
            stats.bytes ?? 0;


    } catch (error) {

        console.error(
            "[!] Failed to load statistics:",
            error
        );
    }
}


// ============================================================
// INITIAL DASHBOARD LOAD
// ============================================================

loadDashboard();


// ============================================================
// AUTO REFRESH
// ============================================================

setInterval(
    loadDashboard,
    5000
);


// ============================================================
// ADD FIREWALL RULE
// ============================================================

const ruleForm =
    document.getElementById("rule-form");


if (ruleForm) {

    ruleForm.addEventListener(
        "submit",
        async function(event) {

            event.preventDefault();


            console.log(
                "[+] Add Rule form submitted"
            );


            // ------------------------------------------------
            // FORM VALUES
            // ------------------------------------------------

            const name =
                document
                    .getElementById("name")
                    .value
                    .trim();


            const action =
                document
                    .getElementById("action")
                    .value;


            const protocol =
                document
                    .getElementById("protocol")
                    .value ||
                "any";


            const sourceIP =
                document
                    .getElementById("source_ip")
                    .value
                    .trim();


            const destinationIP =
                document
                    .getElementById("destination_ip")
                    .value
                    .trim();


            const sourcePortValue =
                document
                    .getElementById("source_port")
                    .value
                    .trim();


            const destinationPortValue =
                document
                    .getElementById("destination_port")
                    .value
                    .trim();


            // ------------------------------------------------
            // VALIDATION
            // ------------------------------------------------

            if (!name) {

                alert(
                    "Please enter a rule name."
                );

                return;
            }


            // ------------------------------------------------
            // BUILD RULE
            // ------------------------------------------------

            const rule = {

                name: name,

                action: action,

                protocol: protocol,

                source_ip:
                    sourceIP || null,

                destination_ip:
                    destinationIP || null,

                source_port:
                    sourcePortValue
                        ? Number(sourcePortValue)
                        : null,

                destination_port:
                    destinationPortValue
                        ? Number(destinationPortValue)
                        : null
            };


            console.log(
                "[+] Sending firewall rule:",
                rule
            );


            // ------------------------------------------------
            // SEND API REQUEST
            // ------------------------------------------------

            try {

                const response =
                    await fetch(
                        "/api/rules",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify(rule)
                        }
                    );


                const result =
                    await response.json();


                console.log(
                    "[+] API response:",
                    result
                );


                // ------------------------------------------------
                // ERROR
                // ------------------------------------------------

                if (!response.ok) {

                    document
                        .getElementById(
                            "rule-message"
                        )
                        .textContent =
                        result.detail ||
                        "Failed to create firewall rule";

                    return;
                }


                // ------------------------------------------------
                // SUCCESS
                // ------------------------------------------------

                document
                    .getElementById(
                        "rule-message"
                    )
                    .textContent =
                    result.message ||
                    "Firewall rule added successfully";


                ruleForm.reset();


                await loadDashboard();


            } catch (error) {

                console.error(
                    "[!] Add rule error:",
                    error
                );


                document
                    .getElementById(
                        "rule-message"
                    )
                    .textContent =
                    "Failed to connect to firewall API";
            }
        }
    );

} else {

    console.error(
        "[!] Firewall rule form not found."
    );
}


// ============================================================
// EDIT FIREWALL RULE
// ============================================================

const editForm =
    document.getElementById(
        "edit-rule-form"
    );


const cancelEditButton =
    document.getElementById(
        "cancel-edit"
    );


if (editForm) {

    editForm.addEventListener(
        "submit",
        async function(event) {

            event.preventDefault();


            const ruleId =
                document
                    .getElementById(
                        "edit-rule-id"
                    )
                    .value;


            const sourcePortValue =
                document
                    .getElementById(
                        "edit-source-port"
                    )
                    .value
                    .trim();


            const destinationPortValue =
                document
                    .getElementById(
                        "edit-destination-port"
                    )
                    .value
                    .trim();


            const rule = {

                name:
                    document
                        .getElementById(
                            "edit-name"
                        )
                        .value
                        .trim(),


                action:
                    document
                        .getElementById(
                            "edit-action"
                        )
                        .value,


                protocol:
                    document
                        .getElementById(
                            "edit-protocol"
                        )
                        .value ||
                    "any",


                source_ip:
                    document
                        .getElementById(
                            "edit-source-ip"
                        )
                        .value
                        .trim() ||
                    null,


                destination_ip:
                    document
                        .getElementById(
                            "edit-destination-ip"
                        )
                        .value
                        .trim() ||
                    null,


                source_port:
                    sourcePortValue
                        ? Number(sourcePortValue)
                        : null,


                destination_port:
                    destinationPortValue
                        ? Number(destinationPortValue)
                        : null,


                enabled:
                    document
                        .getElementById(
                            "edit-enabled"
                        )
                        .checked,


                description:
                    "",


                priority:
                    100
            };


            console.log(
                "[+] Updating firewall rule:",
                ruleId,
                rule
            );


            try {

                const response =
                    await fetch(
                        `/api/rules/${ruleId}`,
                        {
                            method: "PUT",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify(rule)
                        }
                    );


                const result =
                    await response.json();


                if (!response.ok) {

                    document
                        .getElementById(
                            "edit-message"
                        )
                        .textContent =
                        result.detail ||
                        "Failed to update rule";

                    return;
                }


                document
                    .getElementById(
                        "edit-message"
                    )
                    .textContent =
                    "Firewall rule updated successfully";


                document
                    .getElementById(
                        "edit-rule-panel"
                    )
                    .style.display =
                    "none";


                await loadDashboard();


            } catch (error) {

                console.error(
                    "[!] Update error:",
                    error
                );


                document
                    .getElementById(
                        "edit-message"
                    )
                    .textContent =
                    "Failed to connect to firewall API";
            }
        }
    );
}


// ============================================================
// CANCEL EDIT
// ============================================================

if (cancelEditButton) {

    cancelEditButton.addEventListener(
        "click",
        function() {

            document
                .getElementById(
                    "edit-rule-panel"
                )
                .style.display =
                "none";
        }
    );
}