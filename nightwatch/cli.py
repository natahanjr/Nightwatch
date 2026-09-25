"""Nightwatch command line interface."""

import argparse
import json
import sys
import threading

from nightwatch import __version__


def _print_json(obj):
    print(json.dumps(obj, indent=2))


def _maybe_export(findings, source, export_path=None, webhook_url=None,
                  webhook_token=None):
    """Persist and/or forward findings if the user asked for it."""
    if not export_path and not webhook_url:
        return
    from nightwatch.export import dispatch
    summary = dispatch(findings, source=source, jsonl_path=export_path,
                       webhook_url=webhook_url, webhook_token=webhook_token)
    print(f"Exported {summary['findings']} finding(s): "
          f"persisted={summary['persisted']}, forwarded={summary['forwarded']}")


def cmd_phish(args):
    from nightwatch.phishing import (check_url, check_file, verify_url,
                                     load_blocklist)
    blocklist = None
    if args.blocklist:
        try:
            blocklist = load_blocklist(args.blocklist)
        except OSError as e:
            print(f"error: could not load blocklist: {e}", file=sys.stderr)
            sys.exit(2)
    if args.url:
        result = check_url(args.url, blocklist=blocklist)
        if args.verify:
            result["verification"] = verify_url(args.url)
    elif args.file:
        try:
            result = check_file(args.file, blocklist=blocklist)
        except OSError as e:
            print(f"error: cannot read {args.file}: {e}", file=sys.stderr)
            sys.exit(2)
        if args.json:
            _print_json(result)
        else:
            print(f"URLs checked: {result['urls_checked']}")
            print(f"Overall verdict: {result['overall_verdict']}")
            for r in result["results"]:
                print(f"  [{r['verdict']:>10}] score={r['score']:3d} "
                      f"{r['url']}")
        findings = result.get("results") or []
        _maybe_export(findings, source="phish")
        sys.exit(0 if result["overall_verdict"] == "safe" else 1)
    else:
        print("error: provide --url or --file", file=sys.stderr)
        sys.exit(2)
    if args.json:
        _print_json(result)
    else:
        print(f"URL: {result['url']}")
        print(f"Host: {result['host']}")
        print(f"Score: {result['score']}/100")
        print(f"Verdict: {result['verdict']}")
        for flag in result["flags"]:
            print(f"  - {flag}")
        verification = result.get("verification")
        if verification:
            print("Live verification:")
            if verification["error"]:
                print(f"  error: {verification['error']}")
            if verification["resolves"]:
                print(f"  resolves to: {', '.join(verification['ips'])}")
            if verification["redirects"]:
                print("  redirect chain:")
                for u in verification["redirects"]:
                    print(f"    -> {u}")
            if verification.get("final_url"):
                print(f"  final destination: {verification['final_url']}")
            if verification["cross_domain_redirect"]:
                print("  WARNING: redirects to a different domain")
    _maybe_export([result], source="phish")
    sys.exit(0 if result["verdict"] == "safe" else 1)


def cmd_pcap(args):
    from nightwatch.network import analyze_pcap
    try:
        result = analyze_pcap(args.file)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
    _maybe_export(result["findings"], source="pcap",
                  export_path=args.export, webhook_url=args.webhook,
                  webhook_token=args.webhook_token)
    if args.json:
        _print_json(result)
        return
    print(f"Packets: {result['packets_total']} "
          f"(parsed: {result['packets_parsed']})")
    print(f"Protocols: {result['protocols']}")
    print(f"Connections: {result['unique_connections']} "
          f"(completed: {result['completed_connections']})")
    if result["http_hosts"]:
        print("Websites visited:")
        for host, n in result["http_hosts"]:
            print(f"  {host}: {n}")
    if result["dns_queries"]:
        print("DNS queries:")
        for domain, n in result["dns_queries"]:
            print(f"  {domain}: {n}")
    if result["tls_sni"]:
        print("TLS SNIs:")
        for sni, n in result["tls_sni"]:
            print(f"  {sni}: {n}")
    print("Top sources:")
    for ip, n in result["top_sources"]:
        print(f"  {ip}: {n}")
    print("Top destination ports:")
    for port, n in result["top_destination_ports"]:
        print(f"  {port}: {n}")
    if result["findings"]:
        print("Findings:")
        for f in result["findings"]:
            print(f"  [{f['severity']}] {f['label']}: {f['detail']}")
    else:
        print("Findings: none")


def cmd_honeypot(args):
    from nightwatch.honeypot import HoneypotLogger, run_tcp, run_http
    import time
    logger = HoneypotLogger(args.out)
    shutdown = threading.Event()
    try:
        if args.http:
            run_http(args.host, args.port, logger, respond=args.respond,
                     shutdown=shutdown)
        else:
            run_tcp(args.host, args.port, logger, respond=args.respond,
                    shutdown=shutdown)
    except KeyboardInterrupt:
        shutdown.set()
    print(f"Logs written to {args.out}")


def cmd_logs(args):
    from nightwatch.logs import (collect, analyze, generate_markdown_report,
                                 load_rules)
    try:
        events = collect(args.path)
    except OSError as e:
        print(f"error: cannot read {args.path}: {e}", file=sys.stderr)
        sys.exit(2)
    rules = None
    if args.rules:
        try:
            rules = load_rules(args.rules)
        except (OSError, ValueError) as e:
            print(f"error: could not load rules from {args.rules}: {e}",
                  file=sys.stderr)
            sys.exit(2)
    if args.out:
        result = generate_markdown_report(
            args.out, events, rules=rules,
            window_seconds=args.window, threshold=args.threshold)
        print(f"Report written to {args.out}")
    else:
        result = analyze(events, rules=rules,
                         window_seconds=args.window, threshold=args.threshold)
    _maybe_export(result["findings"], source="logs",
                  export_path=args.export, webhook_url=args.webhook,
                  webhook_token=args.webhook_token)
    if args.json:
        _print_json(result)
        return
    print(f"Events: {result['events_total']}")
    print(f"Levels: {result['levels']}")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['label']}: {f['count']} "
              f"(sample: {f['sample']})")
    for b in result["bursts"]:
        print(f"  [!] burst: {b['source']} -> {b['count']} events "
              f"at {b['window_start']}")


def cmd_web(args):
    from nightwatch.web import run_web, set_api_token, set_blocklist
    if args.token:
        set_api_token(args.token)
    if args.blocklist:
        try:
            set_blocklist(args.blocklist)
        except OSError as e:
            print(f"error: could not load blocklist: {e}", file=sys.stderr)
            sys.exit(2)
    run_web(host=args.host, port=args.port,
            open_browser=not args.no_browser)


def main():
    parser = argparse.ArgumentParser(
        prog="nightwatch",
        description="Nightwatch cybersecurity toolkit",
    )
    parser.add_argument("--version", action="version",
                        version=f"nightwatch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_phish = sub.add_parser("phish", help="check a URL or file for phishing")
    p_phish.add_argument("--url", help="URL to check")
    p_phish.add_argument("--file", help="text file (email body) to scan")
    p_phish.add_argument("--verify", action="store_true",
                          help="live check: DNS resolution and redirect chain")
    p_phish.add_argument("--blocklist", default=None,
                         help="path to a threat-intel blocklist file")
    p_phish.add_argument("--json", action="store_true")
    p_phish.add_argument("--export", default=None,
                         help="append findings to this JSONL file")
    p_phish.add_argument("--webhook", default=None,
                         help="POST findings to this URL (SIEM/collector)")
    p_phish.add_argument("--webhook-token", default=None,
                         help="bearer token for --webhook")
    p_phish.set_defaults(func=cmd_phish)

    p_pcap = sub.add_parser("pcap", help="analyze a pcap traffic capture")
    p_pcap.add_argument("file", help="path to .pcap/.pcapng file")
    p_pcap.add_argument("--json", action="store_true")
    p_pcap.add_argument("--export", default=None,
                        help="append findings to this JSONL file")
    p_pcap.add_argument("--webhook", default=None,
                        help="POST findings to this URL (SIEM/collector)")
    p_pcap.add_argument("--webhook-token", default=None,
                        help="bearer token for --webhook")
    p_pcap.set_defaults(func=cmd_pcap)

    p_honeypot = sub.add_parser("honeypot", help="run a TCP or HTTP honeypot")
    p_honeypot.add_argument("--host", default="0.0.0.0")
    p_honeypot.add_argument("--port", type=int, default=8080)
    p_honeypot.add_argument("--out", default="honeypot.jsonl",
                            help="JSONL log file")
    p_honeypot.add_argument("--http", action="store_true",
                            help="fake HTTP server instead of raw TCP")
    p_honeypot.add_argument("--respond", default=None,
                            help="text to send back to each client")
    p_honeypot.set_defaults(func=cmd_honeypot)

    p_logs = sub.add_parser("logs", help="analyze log files")
    p_logs.add_argument("path", help="log file or directory")
    p_logs.add_argument("--out", default=None,
                        help="write a markdown report to this path")
    p_logs.add_argument("--rules", default=None,
                         help="JSON file with custom detection rules")
    p_logs.add_argument("--window", type=int, default=60,
                        help="burst detection window in seconds (default 60)")
    p_logs.add_argument("--threshold", type=int, default=10,
                        help="events per window to flag a burst (default 10)")
    p_logs.add_argument("--json", action="store_true")
    p_logs.add_argument("--export", default=None,
                        help="append findings to this JSONL file")
    p_logs.add_argument("--webhook", default=None,
                        help="POST findings to this URL (SIEM/collector)")
    p_logs.add_argument("--webhook-token", default=None,
                        help="bearer token for --webhook")
    p_logs.set_defaults(func=cmd_logs)

    p_web = sub.add_parser("web", help="launch the web dashboard")
    p_web.add_argument("--host", default="127.0.0.1")
    p_web.add_argument("--port", type=int, default=8000)
    p_web.add_argument("--token", default=None,
                        help="require this bearer token on API writes")
    p_web.add_argument("--blocklist", default=None,
                        help="path to a threat-intel blocklist file")
    p_web.add_argument("--no-browser", action="store_true",
                        help="do not open the browser automatically")
    p_web.set_defaults(func=cmd_web)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
