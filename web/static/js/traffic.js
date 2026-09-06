let selectedRange = "1h";


function formatBytes(bytes) {

    if (!bytes || bytes <= 0) {
        return "0 B";
    }

    const units = ["B", "KB", "MB", "GB"];

    let value = bytes;
    let index = 0;

    while (value >= 1024 && index < units.length - 1) {
        value /= 1024;
        index++;
    }

    return `${value.toFixed(1)} ${units[index]}`;
}


function renderProtocols(protocols) {

    const container =
        document.getElementById("protocol-distribution");

    if (!container) {
        return;
    }

    container.innerHTML = "";

    const entries = Object.entries(protocols || {})
        .sort((a, b) => b[1].packets - a[1].packets);

    if (!entries.length) {

        container.innerHTML = `
            <div class="empty-state">
                No protocol data available.
            </div>
        `;

        return;
    }


    entries.forEach(([protocol, data]) => {

        const item = document.createElement("div");

        item.className = "protocol-item";

        item.innerHTML = `
            <div>
                <strong>${protocol.toUpperCase()}</strong>
            </div>

            <span>
                ${data.packets} packets ·
                ${formatBytes(data.bytes)}
            </span>
        `;

        container.appendChild(item);

    });

}


function renderTraffic(data) {

    const container =
        document.getElementById("traffic-chart");

    if (!container) {
        return;
    }

    const statistics = data.time_statistics || [];

    if (!statistics.length) {

        container.innerHTML = `
            <div class="empty-state">
                No traffic data available.
            </div>
        `;

        return;
    }

    container.innerHTML = "";

    const maxPackets = Math.max(
        ...statistics.map(item => item.packets || 0),
        1
    );


    statistics.forEach(item => {

        const row = document.createElement("div");

        row.className = "traffic-row";

        const width =
            ((item.packets || 0) / maxPackets) * 100;

        row.innerHTML = `
            <div class="traffic-row-label">
                <span>${item.time}</span>
                <span>${item.packets} packets</span>
            </div>

            <div class="traffic-bar">
                <div
                    class="traffic-bar-fill"
                    style="width: ${width}%"
                ></div>
            </div>
        `;

        container.appendChild(row);

    });

}


async function loadTraffic() {

    try {

        const response =
            await fetch(
                `/api/statistics?range=${selectedRange}`,
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


        document.getElementById(
            "packet-count"
        ).textContent =
            data.total_packets ?? 0;


        document.getElementById(
            "accepted-count"
        ).textContent =
            data.accepted_packets ?? 0;


        document.getElementById(
            "dropped-count"
        ).textContent =
            data.dropped_packets ?? 0;


        document.getElementById(
            "byte-count"
        ).textContent =
            formatBytes(data.total_bytes ?? 0);


        renderProtocols(
            data.protocols || {}
        );


        renderTraffic(data);


        const updated =
            document.getElementById("last-updated");

        if (updated) {

            updated.textContent =
                `Last updated: ${new Date().toLocaleTimeString()}`;

        }


    } catch (error) {

        console.error(
            "Failed to load traffic:",
            error
        );

    }

}


document
    .querySelectorAll(".time-range-button")
    .forEach(button => {

        button.addEventListener(
            "click",
            () => {

                document
                    .querySelectorAll(".time-range-button")
                    .forEach(item =>
                        item.classList.remove("active")
                    );

                button.classList.add("active");

                selectedRange =
                    button.dataset.range;

                loadTraffic();

            }
        );

    });


const refreshButton =
    document.getElementById("refresh-button");

if (refreshButton) {

    refreshButton.addEventListener(
        "click",
        loadTraffic
    );

}


loadTraffic();


setInterval(
    loadTraffic,
    5000
);