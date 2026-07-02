# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""conwrt discover — scan the local subnet for routers and show a ranked list.

Thin dispatcher over scripts/discover.py so it integrates with the
``conwrt <subcommand>`` registry in conwrt/__init__.py.
"""
import argparse
import sys


def cmd_discover(args: argparse.Namespace) -> int:
    from discover import DEFAULT_PORTS, discover, format_table, to_json

    try:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    except (ValueError, AttributeError):
        ports = list(DEFAULT_PORTS)

    if not args.json_output and not args.subnet and not args.interface:
        sys.stderr.write("[discover] scanning local subnet (pass --subnet to override)...\n")

    try:
        routers = discover(
            subnet=args.subnet,
            interface=args.interface,
            ports=ports,
            timeout=args.timeout,
            enrich_hosts=not args.no_enrich,
            use_nmap=False if args.no_nmap else None,
        )
    except SystemExit as e:
        sys.stderr.write(f"{e}\n")
        return 2

    if getattr(args, "min_score", 0):
        routers = [r for r in routers if r.router_score >= args.min_score]

    if args.json_output:
        print(to_json(routers))
    else:
        print(format_table(routers))
    return 0
