"""Smoke test for the benchmark harness (small N)."""
from __future__ import annotations

from blhawk.benchmark import run_benchmark


def test_run_benchmark_small():
    result = run_benchmark(urls=20, threads=8)
    assert result["urls"] == 20
    assert result["elapsed_s"] > 0
    assert result["urls_per_sec"] > 0
    assert result["peak_mem_kb"] > 0
