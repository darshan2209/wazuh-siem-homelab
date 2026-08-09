#!/usr/bin/env python3
"""Drain the Zeek Kafka topic into the Wazuh/OpenSearch indexer.

This is the consumer half of the decoupling story. Zeek produces into Kafka and
never blocks; this process reads from its committed offset and bulk-writes into
OpenSearch. Kill it for ten minutes, start it again, and it catches up from
where it stopped instead of losing the window. That is the demonstration.

    export OPENSEARCH_PASSWORD=...
    ./kafka_to_opensearch.py

To show the point in an interview: stop this consumer, run replay_attacks.sh,
start it again, and show the events arriving late but complete. Record the
consumer lag from:

    kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
        --group zeek-to-opensearch --describe
"""

from __future__ import annotations

import json
import os
import signal
import sys
from datetime import datetime, timezone

import urllib3
from kafka import KafkaConsumer
from opensearchpy import OpenSearch, helpers

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BROKER = os.environ.get("KAFKA_BROKER", "127.0.0.1:9092")
TOPIC = os.environ.get("KAFKA_TOPIC", "zeek")
GROUP = os.environ.get("KAFKA_GROUP", "zeek-to-opensearch")
OS_HOST = os.environ.get("OPENSEARCH_HOST", "https://127.0.0.1:9200")
OS_USER = os.environ.get("OPENSEARCH_USER", "admin")
BATCH = int(os.environ.get("BATCH_SIZE", "500"))

_running = True


def stop(_signum, _frame):
    global _running
    _running = False
    print("\nshutting down, committing offsets")


def index_for(record: dict) -> str:
    """One index per Zeek log type per day: zeek-dns-2026.08.03 etc."""
    path = str(record.get("_path", "unknown")).lower()
    path = "".join(c for c in path if c.isalnum() or c == "-")[:32] or "unknown"
    day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"zeek-{path}-{day}"


def main() -> int:
    password = os.environ.get("OPENSEARCH_PASSWORD", "").strip()
    if not password:
        sys.exit("OPENSEARCH_PASSWORD is not set. Export it; do not hardcode it.")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    client = OpenSearch(
        OS_HOST, http_auth=(OS_USER, password),
        verify_certs=False, ssl_show_warn=False, timeout=30,
    )
    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=BROKER,
        group_id=GROUP,
        # earliest, so a restart replays anything the group has not committed.
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        value_deserializer=lambda b: b.decode("utf-8", errors="replace"),
        consumer_timeout_ms=2000,
    )

    print(f"consuming {TOPIC} from {BROKER} -> {OS_HOST}")
    batch, total, bad = [], 0, 0

    while _running:
        for message in consumer:
            if not _running:
                break
            try:
                record = json.loads(message.value)
                if not isinstance(record, dict):
                    raise ValueError("not an object")
            except (json.JSONDecodeError, ValueError):
                bad += 1
                continue
            record["@timestamp"] = datetime.now(timezone.utc).isoformat()
            batch.append({"_index": index_for(record), "_source": record})

            if len(batch) >= BATCH:
                helpers.bulk(client, batch, raise_on_error=False)
                consumer.commit()
                total += len(batch)
                print(f"indexed {total} events ({bad} unparseable)", end="\r")
                batch = []

    if batch:
        helpers.bulk(client, batch, raise_on_error=False)
        consumer.commit()
        total += len(batch)

    consumer.close()
    print(f"\nindexed {total} events, {bad} unparseable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
