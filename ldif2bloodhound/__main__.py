from __future__ import annotations

import argparse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            """Convert LDIF files to JSON files ingestible by BloodHound

Based on ADExplorerSnapshot.py. By Adrian Vollmer, SySS GmbH."""
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "base_dn",
        type=str,
        help="path to the base DN LDIF file (e.g. DC=corp,DC=local)",
    )

    parser.add_argument(
        "schema",
        type=str,
        help="path to the schema LDIF file (e.g. CN=Schema,CN=Configuration,...)",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="path to the output directory (default: %(default)s)",
    )

    return parser.parse_args()


def main() -> None:
    import sys
    from pathlib import Path

    from adexpsnapshot import ADExplorerSnapshot

    from ldif2bloodhound.parser import LDIFSnapshot

    args: argparse.Namespace = parse_args()

    output_dir: Path = Path(args.output_dir)
    if not output_dir.is_dir():
        print(
            f"Error: output directory '{args.output_dir}' does not exist or is not a directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    LDIFSnapshot.schema_path = Path(args.schema)

    ades: ADExplorerSnapshot = ADExplorerSnapshot(
        Path(args.base_dn),
        args.output_dir,
        snapshot_parser=LDIFSnapshot,
    )

    # ADExplorerSnapshot derives the cache path from self.snapfile.name by
    # replacing ".dat" with ".cache".  That breaks for .ldif inputs (the
    # name is unchanged, so the pickle would overwrite the input file).
    # Fix: point snapfile at a .dat name inside the output directory so the
    # upstream logic produces "<output_dir>/<stem>.cache".
    ades.snapfile = output_dir / (Path(args.base_dn).stem + ".dat")

    ades.outputBloodHound()


if __name__ == "__main__":
    main()
