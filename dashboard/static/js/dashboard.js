const datasetSelect = document.getElementById("dataset");
const deviceSelect = document.getElementById("rssi-device");

let rssiChart = null;
let currentObservations = [];
let deviceChart = null;
let currentDeviceAddress = null;

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
            row.classList.add("clickable");
            row.title = "Click to inspect this device";
            row.tabIndex = 0;
            row.setAttribute("role", "button");

            row.addEventListener("click", () => {
                openDevice(device.address);
            });

            row.addEventListener("keydown", event => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    openDevice(device.address);
                }
            });

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

function formatTimestamp(timestamp) {
    return new Date(timestamp * 1000).toLocaleString();
}

function renderSignatures(elementId, signatures) {
    const tbody = document.getElementById(elementId);
    tbody.replaceChildren();

    if (signatures.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 2;
        cell.textContent = "No payload signatures observed.";

        row.appendChild(cell);
        tbody.appendChild(row);
        return;
    }

    for (const item of signatures) {
        const row = document.createElement("tr");

        const signature = document.createElement("td");
        signature.textContent = item.signature;

        const count = document.createElement("td");
        count.textContent = item.count;

        row.append(signature, count);
        tbody.appendChild(row);
    }
}

function renderDeviceChart(observations, address) {
    const canvas = document.getElementById("device-rssi-chart");

    const labels = observations.map(sample =>
        new Date(sample.timestamp * 1000).toLocaleTimeString()
    );

    const values = observations.map(sample => sample.rssi);

    if (deviceChart) {
        deviceChart.destroy();
    }

    deviceChart = new Chart(canvas, {
        type: "line",
        data: {
            labels,
            datasets: [{
                label: address,
                data: values,
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

async function openDevice(address) {
    currentDeviceAddress = address;

    const panel = document.getElementById("device-explorer");

    try {
        const dataset = datasetSelect.value;

        const response = await fetch(
            `/api/device?dataset=${encodeURIComponent(dataset)}` +
            `&address=${encodeURIComponent(address)}`
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error);
        }

        document.getElementById("device-title").textContent =
            data.address;

        document.getElementById("device-subtitle").textContent =
            `${data.dataset} · ${data.samples} observations · ` +
            (data.eligible ? "Eligible" : "Insufficient data");

        document.getElementById("device-mean-rssi").textContent =
            `${data.rssi.mean} dBm`;

        document.getElementById("device-rssi-stddev").textContent =
            `${data.rssi.stddev} dB`;

        document.getElementById("device-manufacturer-bytes").textContent =
            data.manufacturer_bytes_mean;

        document.getElementById("device-service-bytes").textContent =
            data.service_data_bytes_mean;

        document.getElementById("device-service-count").textContent =
            data.service_count_mean;

        document.getElementById("device-samples").textContent =
            data.samples;

        document.getElementById("device-first-seen").textContent =
            formatTimestamp(data.first_seen);

        document.getElementById("device-last-seen").textContent =
            formatTimestamp(data.last_seen);

        renderSignatures(
            "manufacturer-signatures",
            data.manufacturer_signatures
        );

        renderSignatures(
            "service-signatures",
            data.service_signatures
        );

        renderDeviceChart(data.observations, data.address);

        panel.hidden = false;
        panel.scrollIntoView({
            behavior: "smooth",
            block: "start",
        });

    } catch (error) {
        console.error(error);
        alert(`Unable to load device: ${error.message}`);
    }
}

function setBaselineStatus(message, type) {
    const status = document.getElementById("baseline-status");

    status.textContent = message;
    status.className = type;
    status.hidden = false;
}

async function runBaselineAction(endpoint, payload, button) {
    const output = document.getElementById("baseline-output");

    button.disabled = true;
    output.textContent = "Processing fingerprint...";

    try {
        const response = await fetch(endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Request failed");
        }

        return data;

    } catch (error) {
        setBaselineStatus(error.message, "error");
        output.textContent = error.message;
        return null;

    } finally {
        button.disabled = false;
    }
}

async function createDeviceBaseline() {
    if (!currentDeviceAddress) {
        return;
    }

    const button = document.getElementById("create-baseline");
    const dataset = document.getElementById("baseline-dataset").value;

    const data = await runBaselineAction(
        "/api/baseline/create",
        {
            dataset,
            address: currentDeviceAddress,
        },
        button
    );

    if (!data) {
        return;
    }

    setBaselineStatus(
        data.payload_available
            ? "RSSI and payload baselines created successfully."
            : "RSSI baseline created. No usable payload baseline was generated.",
        data.payload_available ? "success" : "warning"
    );

    document.getElementById("baseline-output").textContent =
        data.rssi_output +
        "\n\n" +
        (data.payload_output || "No payload baseline available.");
}

async function compareDeviceBaseline() {
    if (!currentDeviceAddress) {
        return;
    }

    const button = document.getElementById("compare-baseline");
    const baselineDataset =
        document.getElementById("baseline-dataset").value;

    const data = await runBaselineAction(
        "/api/baseline/compare",
        {
            baseline_dataset: baselineDataset,
            dataset: datasetSelect.value,
            address: currentDeviceAddress,
        },
        button
    );

    if (!data) {
        return;
    }

    setBaselineStatus(
        data.assessment,
        data.exit_code === 0 ? "success" : "warning"
    );

    document.getElementById("baseline-output").textContent =
        `Baseline dataset: ${data.baseline_dataset}\n` +
        `Comparison dataset: ${data.comparison_dataset}\n` +
        `Payload comparison: ${
            data.payload_comparison ? "Enabled" : "Unavailable"
        }\n\n` +
        data.output;
}

  document.getElementById("create-baseline")
      .addEventListener("click", createDeviceBaseline);

  document.getElementById("compare-baseline")
      .addEventListener("click", compareDeviceBaseline);

  document.getElementById("close-device").addEventListener("click", () => {
      document.getElementById("device-explorer").hidden = true;
});

deviceSelect.addEventListener("change", updateRssiChart);

datasetSelect.addEventListener("change", () => {
    currentDeviceAddress = null;

    document.getElementById("device-explorer").hidden = true;

    loadDashboard();
});

initializeChart();
loadDashboard();
