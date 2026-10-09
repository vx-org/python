"""Create public source receipts while retaining original acquisition evidence."""

from __future__ import annotations

import hashlib
import json
import urllib.parse
from pathlib import Path


def public_acquisition(value):
    """Omit temporary final-redirect queries; preserve actual requested URLs."""
    if isinstance(value, list):
        return [public_acquisition(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: public_acquisition(item) for key, item in value.items()}
    if result.get("final_url"):
        parsed = urllib.parse.urlsplit(result["final_url"])
        if parsed.query:
            result["final_url"] = urllib.parse.urlunsplit(parsed._replace(query=""))
            result["final_url_query_omitted"] = "Temporary redirect parameters omitted; original acquisition receipt retained locally."
    return result


def update_public_retention(root: Path, retention: dict, recipe: dict) -> None:
    """Update only the public metadata copy and its recipe identity."""
    if retention.get("status") != "complete-local-verified" or retention.get("notice_error") is not None:
        raise ValueError("public source receipts require completed source and notice verification")
    content = (json.dumps(public_acquisition(retention), indent=2) + "\n").encode("utf-8")
    destination = root / "metadata" / "source-retention.json"
    destination.write_bytes(content)
    record = {
        "source": "metadata/source-retention.json",
        "destination": "upstream-metadata/source-retention.json",
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    recipe["metadata"] = [item for item in recipe["metadata"] if item["source"] != record["source"]]
    recipe["metadata"].append(record)
