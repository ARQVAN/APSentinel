import argparse
import csv
from collections import defaultdict


def main():
    parser = argparse.ArgumentParser(
        description="Find identical BLE payloads advertised by multiple addresses."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="data/phone_toggle.tsv",
        help="Observation TSV file (default: data/phone_toggle.tsv)",
    )
    args = parser.parse_args()

    payload_addresses = defaultdict(set)
    payload_counts = defaultdict(int)

    with open(args.input, newline="") as file:
        for row in csv.DictReader(file, delimiter="\t"):
            address = row["address"]

            for field in ("manufacturer_hex", "service_data_hex"):
                for payload in row[field].split(";"):
                    if not payload:
                        continue

                    key = (field, payload)
                    payload_addresses[key].add(address)
                    payload_counts[key] += 1

    matches = [
        (field, payload, addresses, payload_counts[(field, payload)])
        for (field, payload), addresses in payload_addresses.items()
        if len(addresses) > 1
    ]

    matches.sort(key=lambda item: item[3], reverse=True)

    if not matches:
        print("No exact payloads shared across multiple addresses.")
    else:
        for field, payload, addresses, count in matches:
            print(f"\n{field}: {payload}")
            print(f"  Distinct addresses: {len(addresses)}")
            print(f"  Addresses: {', '.join(sorted(addresses))}")
            print(f"  Total observations: {count}")

        print(f"\nShared payloads found: {len(matches)}")

    print("Correlation only: shared payloads do not prove device identity.")


if __name__ == "__main__":
    main()
