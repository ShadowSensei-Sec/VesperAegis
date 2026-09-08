let allEvents = [];

let refreshTimer = null;

const searchInput =
    document.getElementById("log-search");

const dateFilter =
    document.getElementById("date-filter");

const actionFilter =
    document.getElementById("action-filter");

const protocolFilter =
    document.getElementById("protocol-filter");

const timeFilter =
    document.getElementById("time-filter");

const resetButton =
    document.getElementById("reset-filters");

const refreshButton =
    document.getElementById("refresh-logs");

const tableBody =
    document.getElementById("logs-table-body");

const resultsCount =
    document.getElementById("results-count");


/* ============================================================
   HTML ESCAPING
   ============================================================ */

function escapeHtml(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/* ============================================================
   DATE / TIME
   ============================================================ */

function parseEventDate(timestamp) {

    if (!timestamp) {
        return null;
    }

    let normalized =
        String(timestamp).replace(" ", "T");

    // SQLite CURRENT_TIMESTAMP is UTC.
    if (!normalized.endsWith("Z")) {
        normalized += "Z";
    }

    const date =
        new Date(normalized);

    if (Number.isNaN(date.getTime())) {
        return null;
    }

    return date;
}


function formatTimestamp(timestamp) {

    const date =
        parseEventDate(timestamp);

    if (!date) {
        return timestamp || "—";
    }

    return new Intl.DateTimeFormat(
        "en-IN",
        {
            timeZone: "Asia/Kolkata",
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: true
        }
    ).format(date);
}
/* ============================================================
   EVENT HELPERS
   ============================================================ */

function getAction(event) {

    return String(
        event.action ||
        "unknown"
    ).toLowerCase();
}


function getProtocol(event) {

    return String(
        event.protocol ||
        "unknown"
    ).toLowerCase();
}


function getDecision(event) {

    return String(
        event.rule_decision ||
        event.action ||
        "unknown"
    ).toLowerCase();
}


function getRuleName(event) {

    if (event.rule_name) {
        return event.rule_name;
    }

    if (
        event.rule_id !== null &&
        event.rule_id !== undefined
    ) {
        return `Rule #${event.rule_id}`;
    }

    return "No Rule";
}


/* ============================================================
   LOADING / EMPTY STATES
   ============================================================ */

function showLoading() {

    if (!tableBody) {
        return;
    }

    tableBody.innerHTML = `
        <tr>
            <td
                colspan="7"
                class="empty-state"
            >
                Loading security events...
            </td>
        </tr>
    `;
}


function showEmpty(message) {

    if (!tableBody) {
        return;
    }

    tableBody.innerHTML = `
        <tr>
            <td
                colspan="7"
                class="empty-state"
            >
                ${escapeHtml(
                    message ||
                    "No security events found."
                )}
            </td>
        </tr>
    `;
}


/* ============================================================
   SUMMARY
   ============================================================ */

function updateSummary(events) {

    const totalElement =
        document.getElementById(
            "total-events"
        );

    const allowedElement =
        document.getElementById(
            "allowed-events"
        );

    const blockedElement =
        document.getElementById(
            "blocked-events"
        );

    const latestElement =
        document.getElementById(
            "latest-event"
        );


    let allowed = 0;
    let blocked = 0;


    events.forEach(event => {

        const action =
            getAction(event);

        const decision =
            getDecision(event);


        if (
            action === "allow" ||
            action === "accepted" ||
            decision === "allow" ||
            decision === "accepted"
        ) {
            allowed++;
        }


        if (
            action === "deny" ||
            action === "drop" ||
            action === "blocked" ||
            decision === "deny" ||
            decision === "drop" ||
            decision === "blocked"
        ) {
            blocked++;
        }

    });


    if (totalElement) {
        totalElement.textContent =
            events.length;
    }


    if (allowedElement) {
        allowedElement.textContent =
            allowed;
    }


    if (blockedElement) {
        blockedElement.textContent =
            blocked;
    }


    if (latestElement) {

        if (events.length > 0) {

            latestElement.textContent =
                formatTimestamp(
                    events[0].timestamp
                );

        } else {

            latestElement.textContent =
                "—";
        }
    }
}


/* ============================================================
   FILTER: TIME RANGE
   ============================================================ */

function matchesTimeRange(
    event,
    range
) {

    if (range === "all") {
        return true;
    }


    const eventDate =
        parseEventDate(
            event.timestamp
        );

    if (!eventDate) {
        return false;
    }


    const now =
        new Date();


    const durations = {

        "1h":
            60 * 60 * 1000,

        "24h":
            24 * 60 * 60 * 1000,

        "7d":
            7 * 24 * 60 * 60 * 1000,

        "30d":
            30 * 24 * 60 * 60 * 1000

    };


    const duration =
        durations[range];


    if (!duration) {
        return true;
    }


    return (
        now.getTime() -
        eventDate.getTime()
    ) <= duration;
}


/* ============================================================
   FILTER: CALENDAR DATE
   ============================================================ */

function matchesDate(
    event,
    selectedDate
) {

    if (!selectedDate) {
        return true;
    }


    const eventDate =
        parseEventDate(
            event.timestamp
        );

    if (!eventDate) {
        return false;
    }


    const year =
        eventDate.getFullYear();

    const month =
        String(
            eventDate.getMonth() + 1
        ).padStart(2, "0");

    const day =
        String(
            eventDate.getDate()
        ).padStart(2, "0"
        );


    const eventDateString =
        `${year}-${month}-${day}`;


    return (
        eventDateString ===
        selectedDate
    );
}


/* ============================================================
   APPLY ALL FILTERS
   ============================================================ */

function applyFilters() {

    const searchTerm =
        searchInput
            ? searchInput.value
                .trim()
                .toLowerCase()
            : "";


    const selectedDate =
        dateFilter
            ? dateFilter.value
            : "";


    const selectedAction =
        actionFilter
            ? actionFilter.value
                .toLowerCase()
            : "all";


    const selectedProtocol =
        protocolFilter
            ? protocolFilter.value
                .toLowerCase()
            : "all";


    const selectedTime =
        timeFilter
            ? timeFilter.value
                .toLowerCase()
            : "all";


    const filteredEvents =
        allEvents.filter(event => {

            const action =
                getAction(event);

            const protocol =
                getProtocol(event);


            const searchableText = [

                event.timestamp,

                event.source_ip,

                event.source_port,

                event.destination_ip,

                event.destination_port,

                event.protocol,

                event.action,

                event.rule_name,

                event.rule_id,

                event.rule_match,

                event.rule_decision

            ]
                .filter(
                    value =>
                        value !== null &&
                        value !== undefined
                )
                .join(" ")
                .toLowerCase();


            const searchMatches =
                !searchTerm ||
                searchableText.includes(
                    searchTerm
                );


            const actionMatches =
                selectedAction === "all" ||
                action === selectedAction;


            const protocolMatches =
                selectedProtocol === "all" ||
                protocol === selectedProtocol;


            const timeMatches =
                matchesTimeRange(
                    event,
                    selectedTime
                );


            const dateMatches =
                matchesDate(
                    event,
                    selectedDate
                );


            return (
                searchMatches &&
                actionMatches &&
                protocolMatches &&
                timeMatches &&
                dateMatches
            );

        });


    renderTable(
        filteredEvents
    );

    updateSummary(
        filteredEvents
    );

    updateResultsCount(
        filteredEvents.length
    );
}


/* ============================================================
   RESULTS COUNT
   ============================================================ */

function updateResultsCount(count) {

    if (!resultsCount) {
        return;
    }

    resultsCount.textContent =
        `Showing ${count} event${count === 1 ? "" : "s"}`;
}


/* ============================================================
   TABLE
   ============================================================ */

function renderTable(events) {

    if (!events.length) {

        showEmpty(
            "No events match the selected filters."
        );

        return;
    }


    tableBody.innerHTML =
        events.map(event => {

            const action =
                getAction(event);

            const protocol =
                getProtocol(event);

            const decision =
                getDecision(event);


            let actionClass =
                "badge-neutral";


            if (
                action === "allow" ||
                action === "accepted"
            ) {

                actionClass =
                    "badge-allow";

            } else if (

                action === "deny" ||
                action === "drop" ||
                action === "blocked"

            ) {

                actionClass =
                    "badge-deny";
            }


            let decisionClass =
                "decision-neutral";


            if (
                decision === "allow" ||
                decision === "accepted"
            ) {

                decisionClass =
                    "decision-allow";

            } else if (

                decision === "deny" ||
                decision === "drop" ||
                decision === "blocked"

            ) {

                decisionClass =
                    "decision-deny";
            }


            const source =
                event.source_ip
                    ? `${escapeHtml(
                        event.source_ip
                    )}${
                        event.source_port
                            ? ":" +
                              escapeHtml(
                                  event.source_port
                              )
                            : ""
                    }`
                    : "Any";


            const destination =
                event.destination_ip
                    ? `${escapeHtml(
                        event.destination_ip
                    )}${
                        event.destination_port
                            ? ":" +
                              escapeHtml(
                                  event.destination_port
                              )
                            : ""
                    }`
                    : "Any";


            return `

                <tr>

                    <td>
                        ${escapeHtml(
                            formatTimestamp(
                                event.timestamp
                            )
                        )}
                    </td>


                    <td>

                        <span
                            class="event-badge ${actionClass}"
                        >
                            ${escapeHtml(
                                action
                            )}
                        </span>

                    </td>


                    <td>

                        <span
                            class="protocol-badge"
                        >
                            ${escapeHtml(
                                protocol.toUpperCase()
                            )}
                        </span>

                    </td>


                    <td class="address-cell">
                        ${source}
                    </td>


                    <td class="address-cell">
                        ${destination}
                    </td>


                    <td>

                        <span class="rule-name">
                            ${escapeHtml(
                                getRuleName(event)
                            )}
                        </span>

                    </td>


                    <td>

                        <span
                            class="decision-badge ${decisionClass}"
                        >
                            ${escapeHtml(
                                decision
                            )}
                        </span>

                    </td>

                </tr>

            `;

        }).join("");
}


/* ============================================================
   LOAD LOGS FROM API
   ============================================================ */

async function loadLogs(
    showLoader = true
) {

    if (showLoader) {
        showLoading();
    }


    try {

        /*
         * Load a large enough window so the
         * calendar can inspect historical
         * events already stored in SQLite.
         */

        const response =
            await fetch(
                "/api/logs?limit=20000",
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


        allEvents =
            Array.isArray(data.events)
                ? data.events
                : [];


        /*
         * API returns newest events first.
         */

        allEvents.sort(
            (a, b) => {

                const dateA =
                    parseEventDate(
                        a.timestamp
                    );

                const dateB =
                    parseEventDate(
                        b.timestamp
                    );


                if (!dateA || !dateB) {
                    return 0;
                }


                return (
                    dateB.getTime() -
                    dateA.getTime()
                );
            }
        );


        applyFilters();


    } catch (error) {

        console.error(
            "[!] Failed to load firewall logs:",
            error
        );


        showEmpty(
            "Failed to load security events."
        );
    }
}


/* ============================================================
   RESET FILTERS
   ============================================================ */

function resetFilters() {

    if (searchInput) {
        searchInput.value = "";
    }


    if (dateFilter) {
        dateFilter.value = "";
    }


    if (actionFilter) {
        actionFilter.value = "all";
    }


    if (protocolFilter) {
        protocolFilter.value = "all";
    }


    if (timeFilter) {
        timeFilter.value = "all";
    }


    applyFilters();
}


/* ============================================================
   EVENT LISTENERS
   ============================================================ */

if (searchInput) {

    searchInput.addEventListener(
        "input",
        applyFilters
    );
}


if (dateFilter) {

    dateFilter.addEventListener(
        "change",
        applyFilters
    );
}


if (actionFilter) {

    actionFilter.addEventListener(
        "change",
        applyFilters
    );
}


if (protocolFilter) {

    protocolFilter.addEventListener(
        "change",
        applyFilters
    );
}


if (timeFilter) {

    timeFilter.addEventListener(
        "change",
        applyFilters
    );
}


if (resetButton) {

    resetButton.addEventListener(
        "click",
        resetFilters
    );
}


if (refreshButton) {

    refreshButton.addEventListener(
        "click",
        () => loadLogs(true)
    );
}


/* ============================================================
   INITIAL LOAD
   ============================================================ */

loadLogs(true);


/* ============================================================
   LIVE LOG REFRESH
   ============================================================ */

/*
 * The database continues receiving events
 * while the packet monitor is running.
 *
 * The browser checks for new records every
 * 5 seconds without resetting the filters.
 */

refreshTimer =
    setInterval(
        () => loadLogs(false),
        5000
    );