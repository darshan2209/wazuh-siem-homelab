"""Tests for the Kafka to OpenSearch consumer's index naming.

index_for() builds the OpenSearch index name from an attacker-influenceable
field (_path comes off the wire via Zeek), so it must never emit a name with a
path separator or other unsafe character.

    pip install kafka-python opensearch-py pytest
    pytest test_kafka_consumer.py -v
"""

import re
import pytest
import kafka_to_opensearch as k


def test_dns_path_maps_cleanly():
    name = k.index_for({"_path": "dns"})
    assert name.startswith("zeek-dns-")


def test_missing_path_becomes_unknown():
    name = k.index_for({})
    assert name.startswith("zeek-unknown-")


@pytest.mark.parametrize("evil", [
    "../../etc/passwd",
    "a/b/c",
    "path with spaces",
    "UPPER",
    "weird$%^&*chars",
])
def test_unsafe_paths_are_sanitised(evil):
    name = k.index_for({"_path": evil})
    # only lowercase alnum and hyphen survive, so no traversal is ever possible
    assert re.fullmatch(r"zeek-[a-z0-9-]*-\d{4}\.\d{2}\.\d{2}", name), name
    assert "/" not in name
    assert ".." not in name.rsplit("-", 1)[0]


def test_long_path_is_truncated():
    name = k.index_for({"_path": "x" * 200})
    # the path component is capped at 32 chars in index_for
    middle = name[len("zeek-"):].rsplit("-", 1)[0]
    assert len(middle) <= 32


def test_date_suffix_present():
    name = k.index_for({"_path": "conn"})
    assert re.search(r"\d{4}\.\d{2}\.\d{2}$", name)
