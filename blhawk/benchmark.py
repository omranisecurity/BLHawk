"""Lightweight benchmark harness for the scan engine.

Runs the full engine pipeline against an in-process local HTTP server so the
numbers reflect BLHawk's overhead (scheduling, detection, parsing) rather than
the internet. Rate limiting is raised for the measurement; the safe defaults
still apply to real scans.

Run with: ``python -m blhawk.benchmark --urls 500 --threads 20``
"""
from __future__ import annotations

import argparse
import threading
import time
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core.config import ScanConfig
from .core.engine import Scanner
from .core.models import Reclaimability, Severity
from .providers.base import StatusProvider


class _BenchHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        # Half the paths are "missing" (404), half "present" (200).
        missing = self.path.endswith("0") or self.path.endswith("2") or self.path.endswith("4")
        body = b"not found" if missing else b"ok"
        self.send_response(404 if missing else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _BenchProvider(StatusProvider):
    name = "bench-local"
    hosts = ("127.0.0.1",)
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.MEDIUM


def run_benchmark(urls: int = 500, threads: int = 20) -> dict:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _BenchHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    base = f"http://127.0.0.1:{port}"
    targets = [f"{base}/path/{i}" for i in range(urls)]

    from .core import engine as engine_mod

    original = engine_mod.find_provider
    engine_mod.find_provider = lambda url: _BenchProvider()
    try:
        scanner = Scanner(
            config=ScanConfig(
                threads=threads,
                global_rate=100000.0,
                per_host_rate=100000.0,
                enable_soft404=False,
                allow_private=True,
            )
        )
        tracemalloc.start()
        start = time.perf_counter()
        findings = scanner.scan(targets)
        elapsed = time.perf_counter() - start
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    finally:
        engine_mod.find_provider = original
        httpd.shutdown()

    n = len(findings)
    return {
        "urls": n,
        "threads": threads,
        "elapsed_s": round(elapsed, 4),
        "urls_per_sec": round(n / elapsed, 1) if elapsed else 0.0,
        "requests_per_sec": round(n / elapsed, 1) if elapsed else 0.0,
        "urls_per_min": round(n / elapsed * 60, 0) if elapsed else 0.0,
        "peak_mem_kb": round(peak / 1024, 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="blhawk-benchmark")
    parser.add_argument("--urls", type=int, default=500)
    parser.add_argument("--threads", type=int, default=20)
    args = parser.parse_args()
    result = run_benchmark(urls=args.urls, threads=args.threads)
    print("BLHawk benchmark (in-process local server, 1 request/URL):")
    for key, value in result.items():
        print(f"  {key:<18} {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
