#!/usr/bin/env python3
"""
Simple test runner for Codetective (located inside tests/).

Discovers and runs unittest-based tests. Ensures the project root is on sys.path.
If no tests are found, exits successfully after a helpful message.
"""

import argparse
import sys
import subprocess
import unittest
from pathlib import Path


def discover_tests(start_dir: str, pattern: str) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    return loader.discover(start_dir=start_dir, pattern=pattern)


def run_tests(start_dir: str, pattern: str, verbose: bool) -> bool:
    # Ensure project root is importable
    tests_dir = Path(__file__).resolve().parent
    project_root = tests_dir.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    # Resolve start directory
    default_dir = Path(start_dir)
    if not default_dir.is_absolute():
        default_dir = (tests_dir / default_dir).resolve()
    if not default_dir.exists():
        default_dir = tests_dir

    suite = discover_tests(str(default_dir), pattern)
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1)
    result = runner.run(suite)

    # Always run mypy type checks by default
    mypy_cfg = tests_dir / "mypy.ini"
    codetective_file = project_root / "codetective.py"
    config_file = project_root / "config" / "config.py"
    mypy_cmd = [
        sys.executable,
        "-m",
        "mypy",
        "--config-file",
        str(mypy_cfg),
        "--no-namespace-packages",
        str(codetective_file),
        str(config_file),
    ]
    try:
        print("Running mypy type checks...")
        cp = subprocess.run(mypy_cmd, check=False)
        if cp.returncode != 0:
            print("mypy reported issues. See output above.")
            return False
    except FileNotFoundError:
        print("mypy is not installed. Install with: pip install mypy")

    # If no tests were run, print a friendly note but still succeed
    if result.testsRun == 0 and not result.errors and not result.failures:
        print(f"No unittest tests found in '{default_dir}'.")
        print("Tip: add files named like 'test_*.py' under the tests/ folder.")
        return True

    return result.wasSuccessful()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Codetective unittest suite")
    parser.add_argument(
        "-s",
        "--start-dir",
        default=".",
        help="Directory (relative to tests/) to start discovery (default: .)",
    )
    parser.add_argument(
        "-p",
        "--pattern",
        default="test_*.py",
        help="Pattern to match test files (default: test_*.py)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()
    ok = run_tests(args.start_dir, args.pattern, args.verbose)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())


