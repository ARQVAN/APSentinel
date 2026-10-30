import csv
import re
import subprocess
from collections import Counter
from pathlib import Path
from statistics import mean, pstdev

from flask import Flask, jsonify, render_template, request

ROOT = Path(__file__).resolve().parent.parent
ROGUE = ROOT / "rogue"
DATA_DIR = ROOT / "data"

DATASETS = {
    "live": "demo_live.tsv",
    "observations": "observations.tsv",
    "phone_baseline": "phone_baseline.tsv",
    "phone_toggle": "phone_toggle.tsv",
}

BASELINE_DIR = ROOT / "dashboard" / "baselines"

ADDRESS_PATTERN = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")

app = Flask(__name__)


def get_dataset(name):
    filename = DATASETS.get(name)

    if filename is None:
        raise ValueError("Unknown dataset")

    path = DATA_DIR / filename

    if not path.is_file():
        raise FileNotFoundError(filename)

    return path


def run_rogue(command, dataset):
    result = subprocess.run(
        [str(ROGUE), command, str(dataset)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)

    return result.stdout


def load_observations(dataset):
    observations = []

    with dataset.open(newline="") as file:
        reader = csv.DictReader(file, delimiter="\t")

        for row in reader:
            observations.append(
                {
                    "timestamp": float(row["timestamp"]),
                    "address": row["address"],
                    "rssi": int(row["rssi"]),
                    "manufacturer_bytes": int(row["manufacturer_bytes"]),
                    "service_count": int(row["service_count"]),
                    "service_data_bytes": int(row["service_data_bytes"]),
                    "manufacturer_hex": row.get("manufacturer_hex", ""),
                    "service_data_hex": row.get("service_data_hex", ""),
                }
            )

    return observations


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/overview")
def overview():
    name = request.args.get("dataset", "live")

    try:
        dataset = get_dataset(name)
        observations = load_observations(dataset)

        report = run_rogue("report", dataset)
        summary = run_rogue("summary", dataset)

        addresses = {}

        for observation in observations:
            address = observation["address"]

            addresses.setdefault(address, []).append(observation)

        devices = []

        for address, samples in addresses.items():
            rssis = [sample["rssi"] for sample in samples]
            mean_rssi = sum(rssis) / len(rssis)

            devices.append(
                {
                    "address": address,
                    "samples": len(samples),
                    "mean_rssi": round(mean_rssi, 2),
                    "eligible": len(samples) >= 20,
                }
            )

        devices.sort(key=lambda device: device["samples"], reverse=True)

        return jsonify(
            {
                "dataset": name,
                "total_observations": len(observations),
                "distinct_addresses": len(devices),
                "eligible_addresses": sum(device["eligible"] for device in devices),
                "devices": devices,
                "observations": observations,
                "summary": summary,
                "report": report,
            }
        )

    except (
        ValueError,
        FileNotFoundError,
        RuntimeError,
        KeyError,
        subprocess.TimeoutExpired,
    ) as error:
        return jsonify({"error": str(error)}), 400


@app.route("/api/correlation")
def correlation():
    name = request.args.get("dataset", "observations")

    try:
        dataset = get_dataset(name)
        output = run_rogue("correlate", dataset)

        return jsonify(
            {
                "dataset": name,
                "output": output,
            }
        )

    except (
        ValueError,
        FileNotFoundError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as error:
        return jsonify({"error": str(error)}), 400


@app.route("/api/device")
def device_details():
    name = request.args.get("dataset", "live")
    address = request.args.get("address", "").strip().upper()

    if not ADDRESS_PATTERN.fullmatch(address):
        return jsonify({"error": "Invalid BLE address"}), 400

    if not address:
        return jsonify({"error": "Missing BLE address"}), 400

    try:
        dataset = get_dataset(name)
        observations = load_observations(dataset)

        samples = [
            observation
            for observation in observations
            if observation["address"].upper() == address
        ]

        if not samples:
            return jsonify({"error": "Device not found"}), 404

        samples.sort(key=lambda item: item["timestamp"])

        rssis = [sample["rssi"] for sample in samples]

        manufacturer_signatures = Counter()
        service_signatures = Counter()

        for sample in samples:
            for field, counter in (
                ("manufacturer_hex", manufacturer_signatures),
                ("service_data_hex", service_signatures),
            ):
                value = sample.get(field, "").strip()

                if value:
                    for signature in value.split(";"):
                        signature = signature.strip()

                        if signature:
                            counter[signature] += 1

        def signature_list(counter):
            return [
                {"signature": signature, "count": count}
                for signature, count in counter.most_common()
            ]

        return jsonify(
            {
                "address": address,
                "dataset": name,
                "samples": len(samples),
                "eligible": len(samples) >= 20,
                "rssi": {
                    "mean": round(mean(rssis), 2),
                    "stddev": round(pstdev(rssis), 2),
                    "minimum": min(rssis),
                    "maximum": max(rssis),
                },
                "manufacturer_bytes_mean": round(
                    mean(sample["manufacturer_bytes"] for sample in samples), 2
                ),
                "service_count_mean": round(
                    mean(sample["service_count"] for sample in samples), 2
                ),
                "service_data_bytes_mean": round(
                    mean(sample["service_data_bytes"] for sample in samples), 2
                ),
                "first_seen": samples[0]["timestamp"],
                "last_seen": samples[-1]["timestamp"],
                "manufacturer_signatures": signature_list(manufacturer_signatures),
                "service_signatures": signature_list(service_signatures),
                "observations": [
                    {
                        "timestamp": sample["timestamp"],
                        "rssi": sample["rssi"],
                    }
                    for sample in samples
                ],
            }
        )

    except (ValueError, FileNotFoundError, RuntimeError, KeyError) as error:
        return jsonify({"error": str(error)}), 400


def baseline_paths(dataset, address):
    if dataset not in DATASETS:
        raise ValueError("Unknown baseline dataset")

    address = address.upper()

    if not ADDRESS_PATTERN.fullmatch(address):
        raise ValueError("Invalid BLE address")

    stem = f"{dataset}_{address.replace(':', '_')}"

    return (
        BASELINE_DIR / f"{stem}_rssi.tsv",
        BASELINE_DIR / f"{stem}_payload.tsv",
    )


@app.route("/api/baseline/create", methods=["POST"])
def create_baseline():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    address = data.get("address", "")

    if not isinstance(address, str):
        return jsonify({"error": "Address must be a string"}), 400

    address = address.strip().upper()

    if not ADDRESS_PATTERN.fullmatch(address):
        return jsonify({"error": "Invalid BLE address"}), 400

    dataset_name = data.get("dataset", "live")

    if not isinstance(dataset_name, str):
        return jsonify({"error": "Dataset must be a string"}), 400

    try:
        dataset = get_dataset(dataset_name)
        rssi_path, payload_path = baseline_paths(dataset_name, address)

        BASELINE_DIR.mkdir(parents=True, exist_ok=True)

        # Generate the RSSI fingerprint baseline.
        result = subprocess.run(
            [
                str(ROGUE),
                "baseline",
                str(dataset),
                address,
                str(rssi_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            return jsonify({"error": result.stderr or result.stdout}), 400

        if payload_path.exists():
            payload_path.unlink()

        # Generate the payload baseline when possible.
        payload_result = subprocess.run(
            [
                str(ROGUE),
                "payload-baseline",
                str(dataset),
                address,
                str(payload_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        payload_available = payload_result.returncode == 0 and payload_path.is_file()

        if not payload_available and payload_path.exists():
            payload_path.unlink()

        return jsonify(
            {
                "success": True,
                "address": address,
                "dataset": dataset_name,
                "payload_available": payload_available,
                "rssi_output": result.stdout,
                "payload_output": (
                    payload_result.stdout
                    if payload_available
                    else payload_result.stderr or payload_result.stdout
                ),
            }
        )

    except (
        ValueError,
        FileNotFoundError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as error:
        return jsonify({"error": str(error)}), 400


@app.route("/api/baseline/compare", methods=["POST"])
def compare_baseline():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    baseline_dataset = data.get("baseline_dataset", "live")
    current_dataset = data.get("dataset", "observations")
    address = data.get("address", "")

    if not isinstance(baseline_dataset, str):
        return jsonify({"error": "Baseline dataset must be a string"}), 400

    if not isinstance(current_dataset, str):
        return jsonify({"error": "Comparison dataset must be a string"}), 400

    if not isinstance(address, str):
        return jsonify({"error": "Address must be a string"}), 400

    address = address.strip().upper()

    if not ADDRESS_PATTERN.fullmatch(address):
        return jsonify({"error": "Invalid BLE address"}), 400

    try:
        current_path = get_dataset(current_dataset)

        rssi_path, payload_path = baseline_paths(baseline_dataset, address)

        if not rssi_path.is_file():
            return jsonify(
                {"error": "No RSSI baseline exists for this device and dataset."}
            ), 404

        command = [
            str(ROGUE),
            "check",
            str(current_path),
            address,
            str(rssi_path),
        ]

        has_payload_baseline = payload_path.is_file()

        if has_payload_baseline:
            command.append(str(payload_path))

        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        # Your CLI uses 0 for no deviations, 1 for significant
        # deviations, and 2 for invalid data/errors.
        if result.returncode not in (0, 1):
            return jsonify({"error": result.stderr or result.stdout}), 400

        return jsonify(
            {
                "success": True,
                "address": address,
                "baseline_dataset": baseline_dataset,
                "comparison_dataset": current_dataset,
                "payload_comparison": has_payload_baseline,
                "exit_code": result.returncode,
                "assessment": (
                    "NO OBSERVED DEVIATIONS"
                    if result.returncode == 0
                    else "OBSERVED DEVIATIONS"
                ),
                "output": result.stdout,
            }
        )

    except (
        ValueError,
        FileNotFoundError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as error:
        return jsonify({"error": str(error)}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
