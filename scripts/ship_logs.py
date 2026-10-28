"""Ship Wazuh / Suricata / ModSecurity JSON logs to API Fortress.

Runs on the sensor host (Wazuh manager, Suricata box, web server). Reads a log
file in batches and POSTs it to /admin/api/ingest/push with the INGEST_TOKEN.
Only the Python standard library is required.

One-off upload of the last 5000 lines:
    python ship_logs.py --file /var/ossec/logs/alerts/alerts.json --url https://fortress.example.com --token TOKEN

Continuous shipping (like `tail -f`), state kept so restarts don't resend:
    python ship_logs.py --file /var/log/suricata/eve.json --source suricata --url ... --token ... --follow
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from collections import deque


def push(url: str, token: str, source: str, name: str, lines: list[str]) -> dict:
    req = urllib.request.Request(
        f"{url.rstrip('/')}/admin/api/ingest/push?source={source}",
        data="\n".join(lines).encode(),
        method="POST",
        headers={"X-Ingest-Token": token, "X-Source-Name": name, "Content-Type": "application/x-ndjson"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", required=True)
    ap.add_argument("--url", required=True, help="gateway base URL")
    ap.add_argument("--token", default=os.getenv("INGEST_TOKEN"), help="INGEST_TOKEN (or set env var)")
    ap.add_argument("--source", default="auto", choices=["auto", "wazuh", "suricata", "modsecurity"])
    ap.add_argument("--batch", type=int, default=500)
    ap.add_argument("--tail", type=int, default=5000, help="lines to send on first run")
    ap.add_argument("--follow", action="store_true", help="keep running and ship new lines")
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--state", default=None, help="offset file (default: <file>.fortress-offset in home dir)")
    args = ap.parse_args()
    if not args.token:
        print("An ingest token is required (--token or INGEST_TOKEN).")
        return 2

    name = f"{socket.gethostname()}:{os.path.basename(args.file)}"
    state = args.state or os.path.join(os.path.expanduser("~"), f".{os.path.basename(args.file)}.fortress-offset")

    def send(lines: list[str]) -> None:
        for i in range(0, len(lines), args.batch):
            chunk = lines[i:i + args.batch]
            for attempt in range(5):
                try:
                    r = push(args.url, args.token, args.source, name, chunk)
                    print(f"batch #{r['id']}: {r['records_parsed']} parsed, {r['alerts']} alerts, {r['records_failed']} failed")
                    break
                except (urllib.error.URLError, TimeoutError) as exc:
                    wait = 2 ** attempt
                    print(f"push failed ({exc}); retrying in {wait}s")
                    time.sleep(wait)
            else:
                raise SystemExit("giving up after repeated failures")

    offset = None
    if os.path.exists(state):
        try:
            offset = int(open(state).read().strip())
        except ValueError:
            offset = None

    with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
        size = os.path.getsize(args.file)
        if offset is None or offset > size:
            initial = [l.rstrip("\n") for l in deque(fh, maxlen=args.tail) if l.strip()]
        else:
            fh.seek(offset)
            initial = [l.rstrip("\n") for l in fh if l.strip()]
        if initial:
            send(initial)
        open(state, "w").write(str(fh.tell()))
        if not args.follow:
            return 0
        print(f"following {args.file} (Ctrl+C to stop)")
        buf: list[str] = []
        while True:
            line = fh.readline()
            if line:
                if line.endswith("\n"):
                    if line.strip():
                        buf.append(line.rstrip("\n"))
                    if len(buf) < args.batch:
                        continue
                else:
                    fh.seek(fh.tell() - len(line))
            if buf:
                send(buf)
                buf = []
                open(state, "w").write(str(fh.tell()))
            if os.path.getsize(args.file) < fh.tell():  # rotated
                print("log rotated; reopening")
                return main()
            time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
