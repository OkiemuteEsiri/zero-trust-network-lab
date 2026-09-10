import argparse
from pathlib import Path
from .loader import load_requests
from .policy_engine import evaluate
from .reporting import markdown


def main():
    parser = argparse.ArgumentParser(description="Offline zero-trust policy assessment")
    parser.add_argument("input", help="Synthetic JSON request file")
    parser.add_argument("--report", default="reports/generated-assessment.md")
    args = parser.parse_args()
    decisions = [evaluate(r) for r in load_requests(args.input)]
    output = markdown(decisions)
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(output, encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
