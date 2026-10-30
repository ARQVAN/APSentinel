const datasetSelect = document.getElementById("dataset");
const deviceSelect = document.getElementById("rssi-device");

let rssiChart = null;
let currentObservations = [];

function initializeChart() {
    const context = document.getElementById("rssi-chart");

    rssiChart = new Chart(context, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "RSSI",
                data: [],
                borderColor: "#38bdf8",
                backgroundColor: "rgba(56, 189, 248, 0.12)",
                borderWidth: 2,
                pointRadius: 2,
                pointHoverRadius: 5,
                tension: 0.25,
                fill: true,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: "index",
            },
            plugins: {
                legend: {
                    display: false,
                },
            },
            scales: {
                x: {
                    ticks: {
                        color: "#94a3b8",
                        maxTicksLimit: 10,
                    },
                    grid: {
                        color: "rgba(148, 163, 184, 0.08)",
                    },
                },
                y: {
                    title: {
                        display: true,
                        text: "RSSI (dBm)",
                        color: "#94a3b8",
                    },
                    ticks: {
                        color: "#94a3b8",
                    },
                    grid: {
                        color: "rgba(148, 163, 184, 0.08)",
                    },
                },
            },
        },
    });
}

function updateRssiChart() {
    const address = deviceSelect.value;

    const samples = currentObservations
        .filter(observation => observation.address === address)
        .sort((a, b) => a.timestamp - b.timestamp);

    const labels = samples.map(sample => {
        return new Date(sample.timestamp * 1000).toLocaleTimeString();
    });

    const values = samples.map(sample => sample.rssi);

    rssiChart.data.labels = labels;
    rssiChart.data.datasets[0].data = values;
    rssiChart.data.datasets[0].label = address;

    rssiChart.update();
}

function updateDeviceSelector(devices) {
    const previousAddress = deviceSelect.value;

    deviceSelect.replaceChildren();

    for (const device of devices) {
        const option = document.createElement("option");

        option.value = device.address;
        option.textContent =
            `${device.address} (${device.samples} samples)`;

        deviceSelect.appendChild(option);
    }

    if (devices.some(device => device.address === previousAddress)) {
        deviceSelect.value = previousAddress;
    } else if (devices.length > 0) {
        deviceSelect.value = devices[0].address;
    }

    updateRssiChart();
}

async function loadDashboard() {
    const dataset = datasetSelect.value;

    try {
        const response = await fetch(
            `/api/overview?dataset=${encodeURIComponent(dataset)}`
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error);
        }

        document.getElementById("observations").textContent =
            data.total_observations;

        document.getElementById("addresses").textContent =
            data.distinct_addresses;

        document.getElementById("eligible").textContent =
            data.eligible_addresses;

        document.getElementById("dataset-label").textContent =
            data.dataset;

        currentObservations = data.observations;

        updateDeviceSelector(data.devices);

        const deviceList = document.getElementById("device-list");
        deviceList.replaceChildren();

        for (const device of data.devices) {
            const row = document.createElement("tr");

            const values = [
                device.address,
                device.samples,
                `${device.mean_rssi} dBm`,
            ];

            for (const value of values) {
                const cell = document.createElement("td");
                cell.textContent = value;
                row.appendChild(cell);
            }

            const status = document.createElement("td");

            status.textContent = device.eligible
                ? "Eligible"
                : "Insufficient data";

            status.className = device.eligible
                ? "status"
                : "insufficient";

            row.appendChild(status);
            deviceList.appendChild(row);
        }

        document.getElementById("report").textContent = data.report;

        const match = data.report.match(
            /Shared payload signatures: (\d+)/
        );

        document.getElementById("signatures").textContent =
            match ? match[1] : "—";

        await loadCorrelation();

    } catch (error) {
        console.error(error);

        document.getElementById("report").textContent =
            `Error: ${error.message}`;
    }
}

async function loadCorrelation() {
    try {
        const response = await fetch(
            "/api/correlation?dataset=observations"
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error);
        }

        document.getElementById("correlation-output").textContent =
            data.output;

    } catch (error) {
        document.getElementById("correlation-output").textContent =
            `Error: ${error.message}`;
    }
}

deviceSelect.addEventListener("change", updateRssiChart);

datasetSelect.addEventListener("change", loadDashboard);

initializeChart();
loadDashboard();
