"""
Build female_names.csv from SSA baby names data.

Usage:
    python build_female_names.py /path/to/ssa_names_dir/

The SSA names directory should contain files named yobYYYY.txt, each with
three columns (no header): name, gender (M/F), count.

Output:
    female_names.csv — two columns: name, female_ratio
    Only names where female_ratio >= FEMALE_NAME_GENDER_THRESHOLD are included.
"""

import argparse
import glob
import os
import sys

import pandas as pd

FEMALE_NAME_GENDER_THRESHOLD = 0.70


def build(ssa_dir: str, output_path: str) -> None:
    pattern = os.path.join(ssa_dir, "yob*.txt")
    files = glob.glob(pattern)
    if not files:
        sys.exit(f"No yobYYYY.txt files found in {ssa_dir!r}")

    print(f"Reading {len(files)} SSA files...")
    chunks = []
    for path in files:
        df = pd.read_csv(path, header=None, names=["name", "gender", "count"])
        chunks.append(df)

    raw = pd.concat(chunks, ignore_index=True)

    totals = raw.groupby(["name", "gender"])["count"].sum().unstack(fill_value=0)
    totals.columns.name = None
    if "F" not in totals.columns:
        totals["F"] = 0
    if "M" not in totals.columns:
        totals["M"] = 0

    totals["total"] = totals["F"] + totals["M"]
    totals["female_ratio"] = totals["F"] / totals["total"]

    female = (
        totals[totals["female_ratio"] >= FEMALE_NAME_GENDER_THRESHOLD][["female_ratio"]]
        .reset_index()
        .rename(columns={"name": "name"})
        .sort_values("female_ratio", ascending=False)
    )

    female.to_csv(output_path, index=False)
    print(f"Wrote {len(female):,} female names to {output_path}")
    print(f"  Threshold used: female_ratio >= {FEMALE_NAME_GENDER_THRESHOLD}")
    print(f"  Sample: {female['name'].head(10).tolist()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build female_names.csv from SSA data")
    parser.add_argument("ssa_dir", help="Directory containing yobYYYY.txt files")
    parser.add_argument(
        "--output",
        default="female_names.csv",
        help="Output CSV path (default: female_names.csv)",
    )
    args = parser.parse_args()
    build(args.ssa_dir, args.output)


if __name__ == "__main__":
    main()
