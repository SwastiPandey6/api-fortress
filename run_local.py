"""Start the protected demo API and the API Fortress gateway together.

Usage:
    python run_local.py              # gateway on :8000, demo API on :9000
    python run_local.py --reload     # auto-reload on code changes (development)

Press Ctrl+C to stop both processes. Works on Windows, macOS and Linux.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def wait_for(url: str, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.5) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Run API Fortress locally")
    parser.add_argument("--host", default="127.0.0.1", help="gateway bind address (use 0.0.0.0 for LAN access)")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    parser.add_argument("--backend-port", type=int, default=9000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    env = os.environ.copy()
    env.setdefault("BACKEND_URL", f"http://127.0.0.1:{args.backend_port}")
    env.setdefault("GATEWAY_SELF_URL", f"http://127.0.0.1:{args.port}")
    (ROOT / "data").mkdir(exist_ok=True)

    py = sys.executable
    reload_flag = ["--reload"] if args.reload else []
    backend_cmd = [py, "-m", "uvicorn", "demo_api.main:app", "--host", "127.0.0.1", "--port", str(args.backend_port),
                   "--log-level", "warning", *reload_flag]
    gateway_cmd = [py, "-m", "uvicorn", "app.main:app", "--host", args.host, "--port", str(args.port),
                   "--proxy-headers", *reload_flag]
    if args.reload:
        gateway_cmd += ["--reload-dir", "app", "--reload-dir", "dashboard"]
        backend_cmd += ["--reload-dir", "demo_api"]

    kwargs = {"cwd": ROOT, "env": env}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]

    print("Starting protected demo API on port", args.backend_port)
    backend = subprocess.Popen(backend_cmd, **kwargs)
    if not wait_for(f"http://127.0.0.1:{args.backend_port}/health"):
        print("Demo API failed to start. Check the output above.")
        backend.terminate()
        return 1

    print("Starting API Fortress gateway on port", args.port)
    gateway = subprocess.Popen(gateway_cmd, **kwargs)
    if wait_for(f"http://127.0.0.1:{args.port}/gateway/health"):
        line = "=" * 64
        print(f"\n{line}\n  API Fortress is running\n")
        print(f"  Dashboard     http://127.0.0.1:{args.port}/dashboard")
        print(f"  Gateway       http://127.0.0.1:{args.port}   (send API requests here)")
        print(f"  Protected API http://127.0.0.1:{args.backend_port} (rejects direct access)")
        print(f"\n  Admin login   {env.get('ADMIN_USERNAME', 'admin')} / see ADMIN_PASSWORD in .env")
        print(f"  Press Ctrl+C to stop.\n{line}\n")

    procs = [gateway, backend]
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
        print("A process exited unexpectedly; shutting down.")
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        for p in procs:
            if p.poll() is None:
                if os.name == "nt":
                    p.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                else:
                    p.terminate()
        for p in procs:
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
