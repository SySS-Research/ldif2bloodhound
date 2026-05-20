def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            """Convert an LDIF file to JSON files ingestible by BloodHound

Based on ADExplorerSnapshot.py. By Adrian Vollmer, SySS GmbH."""
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "input",
        type=str,
        help="path to the input LDIF file",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="path to the output directory (default: %(default)s)",
    )

    args = parser.parse_args()

    return args


def main() -> None:
    from pathlib import Path
    from adexpsnapshot import ADExplorerSnapshot
    from ldif2bloodhound.parser import LDIFSnapshot

    args = parse_args()

    ades = ADExplorerSnapshot(
        Path(args.input),
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
