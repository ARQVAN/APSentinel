import csv
import subprocess
from pathlib import Path

from flask import Flask, jsonify, render_template, request

ROOT = Path(__file__).resolve().parent.parent
ROGUE = ROOT / "rogue"
DATA_DIR = ROOT / "data"

DATASETS = {
    "live": "demo_live.tsv",
    "observations": "observations.tsv",
}

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

    except (ValueError, FileNotFoundError, RuntimeError, KeyError) as error:
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

    except (ValueError, FileNotFoundError, RuntimeError) as error:
        return jsonify({"error": str(error)}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
