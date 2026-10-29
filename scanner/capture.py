import argparse
import asyncio
import csv
import time
from pathlib import Path

from bleak import BleakScanner


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--out", default="data/observations.tsv")
    args = parser.parse_args()

    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)

    queue = asyncio.Queue()
    count = 0
    stop = object()

    async def writer_task():
        # File operations run in a worker thread.
        def open_output():
            file = output.open("w", newline="")
            writer = csv.writer(file, delimiter="\t")
            writer.writerow(
                [
                    "timestamp",
                    "address",
                    "rssi",
                    "manufacturer_bytes",
                    "service_count",
                    "service_data_bytes",
                ]
            )
            file.flush()
            return file, writer

        file, writer = await asyncio.to_thread(open_output)

        try:
            while True:
                row = await queue.get()

                try:
                    if row is stop:
                        break

                    await asyncio.to_thread(writer.writerow, row)
                    await asyncio.to_thread(file.flush)
                finally:
                    queue.task_done()
        finally:
            await asyncio.to_thread(file.close)

    def on_advertisement(device, advertisement):
        nonlocal count

        row = [
            f"{time.time():.3f}",
            device.address,
            advertisement.rssi,
            sum(len(payload) for payload in advertisement.manufacturer_data.values()),
            len(advertisement.service_uuids),
            sum(len(payload) for payload in advertisement.service_data.values()),
        ]

        # The callback is synchronous, so schedule queue insertion
        # on the event loop instead of awaiting it here.
        queue.put_nowait(row)

        count += 1
        if count % 10 == 0:
            print(f"\rCaptured {count} observations", end="", flush=True)

    writer = asyncio.create_task(writer_task())

    try:
        print(f"Scanning for {args.seconds} seconds...")

        async with BleakScanner(detection_callback=on_advertisement):
            await asyncio.sleep(args.seconds)
    finally:
        # Drain queued observations before closing the output file.
        await queue.put(stop)
        await writer

    print(f"\nSaved {count} observations to {output}")


if __name__ == "__main__":
    asyncio.run(main())
