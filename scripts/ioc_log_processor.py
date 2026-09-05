#!/usr/bin/env python3
"""Simple SOC alert-processing helper for exported lab data.

Reads a CSV containing alert records, normalizes common fields, assigns a
review priority, and writes a case-ready CSV. This is intentionally a small
portfolio exercise rather than a claim of production SOAR capability.
"""

import argparse
import csv
from pathlib import Path


def priority(severity: str) -> str:
    value = severity.strip().lower()
    return {
        "critical": "P1",
        "high": "P2",
        "medium": "P3",
        "low": "P4",
    }.get(value, "Review")


def process(input_path: Path, output_path: Path) -> None:
    with input_path.open("r", newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError("Input CSV has no header row")

        required = {"signature", "severity"}
        missing = required - set(reader.fieldnames)
        if missing:
            raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")

        fields = list(reader.fieldnames) + ["priority", "recommended_disposition"]
        rows = []
        for row in reader:
            severity = row.get("severity", "")
            row["priority"] = priority(severity)
            row["recommended_disposition"] = (
                "Needs Investigation" if severity.strip().lower() in {"critical", "high"}
                else "Review"
            )
            rows.append(row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Processed {len(rows)} alert(s) -> {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare exported SOC alerts for case review")
    parser.add_argument("input", type=Path, help="Input alert CSV")
    parser.add_argument("output", type=Path, help="Output case-ready CSV")
    args = parser.parse_args()
    process(args.input, args.output)
