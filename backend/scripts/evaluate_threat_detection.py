"""Run the deterministic threat benchmark from the backend directory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from threats.benchmark import evaluate_threat_dataset


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        default="tests/fixtures/threat_detection_benchmark.json",
        help="Path to a labeled threat benchmark JSON file.",
    )
    parser.add_argument("--output", help="Optional path to write the evaluation report.")
    parser.add_argument(
        "--check-determinism",
        action="store_true",
        help="Evaluate twice and fail if canonical report hashes differ.",
    )
    args = parser.parse_args()

    dataset = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    report = evaluate_threat_dataset(dataset)
    if args.check_determinism:
        second = evaluate_threat_dataset(dataset)
        if report["report_sha256"] != second["report_sha256"]:
            raise SystemExit("Threat benchmark is not deterministic.")
    rendered = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
