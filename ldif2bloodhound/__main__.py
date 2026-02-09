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
    from adexpsnapshot import ADExplorerSnapshot
    from ldif2bloodhound.parser import LDIFSnapshot

    args = parse_args()

    ades = ADExplorerSnapshot(
        args.input,
        args.output_dir,
        snapshot_parser=LDIFSnapshot,
    )

    ades.outputBloodHound()


if __name__ == "__main__":
    main()
