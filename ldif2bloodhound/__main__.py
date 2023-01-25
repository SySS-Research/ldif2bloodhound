def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            """Convert an LDIF file to JSON files ingestible by BloodHound

Based on ADExplorerSnapshot.py. By Adrian Vollmer, SySS GmbH."""),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        'input',
        type=str,
        help="path to the input LDIF file",
    )

    parser.add_argument(
        '-o', '--output-dir',
        default='.',
        help="path to the output directory (default: %(default)s)",
    )

    args = parser.parse_args()

    return args


def main():
    import logging

    import pwnlib
    from adexpsnapshot import ADExplorerSnapshot
    from ldif2bloodhound.parser import LDIFSnapshot

    logging.basicConfig(handlers=[pwnlib.log.console])
    log = pwnlib.log.getLogger(__name__)
    log.setLevel(20)

    if pwnlib.term.can_init():
        pwnlib.term.init()
    log.term_mode = pwnlib.term.term_mode

    args = parse_args()

    ades = ADExplorerSnapshot(
        args.input,
        args.output,
        log=log,
        snapshot_parser=LDIFSnapshot,
    )

    ades.outputBloodHound()


if __name__ == '__main__':
    main()
