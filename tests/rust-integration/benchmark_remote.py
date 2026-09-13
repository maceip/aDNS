#!/usr/bin/env python3
"""Measure public authoritative DNS under a fixed, non-mutating DO=1 load."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import pathlib
import re
import statistics
import subprocess
import time

import dns.flags
import dns.message
import dns.query
import dns.rcode


def sample_window(probe, seconds, rate):
    """Schedule bounded concurrent probes; report missed slots without bursts."""
    started = time.monotonic()
    started_unix = time.time()
    count = int(seconds * rate)
    # Each network operation has a two-second timeout. Bound threads and the
    # pending set independently of response speed; never queue unbounded work.
    limit = min(64, max(4, rate * 2 + 2))
    samples, failures, pending = [], [], set()

    def perform(index, target):
        actual = time.monotonic()
        row = {"sample_index": index, "scheduled_elapsed_seconds": index / rate,
               "started_elapsed_seconds": actual - started,
               "dispatch_lag_seconds": actual - target}
        if actual >= started + seconds:
            return False, dict(row, attempted=False, error="dispatch_after_window")
        before = time.perf_counter_ns()
        try:
            query = probe(index)
            return True, dict(row, attempted=True, query=query,
                              elapsed_seconds=time.monotonic() - started,
                              latency_ms=(time.perf_counter_ns() - before) / 1e6)
        except Exception as error:
            return False, dict(row, attempted=True,
                               elapsed_seconds=time.monotonic() - started,
                               error=type(error).__name__)

    def collect(done):
        for future in done:
            passed, row = future.result()
            (samples if passed else failures).append(row)

    with ThreadPoolExecutor(max_workers=limit) as executor:
        for index in range(count):
            target = started + index / rate
            delay = target - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            done = {future for future in pending if future.done()}
            collect(done)
            pending.difference_update(done)
            now = time.monotonic()
            reason = None
            if now >= started + seconds or now - target >= 1 / rate:
                reason = "missed_schedule_slot"
            elif len(pending) >= limit:
                reason = "bounded_probe_capacity"
            if reason:
                failures.append({"sample_index": index, "attempted": False,
                                 "scheduled_elapsed_seconds": index / rate,
                                 "elapsed_seconds": now - started, "error": reason})
            else:
                pending.add(executor.submit(perform, index, target))
        collect(pending)
    samples.sort(key=lambda row: row["sample_index"])
    failures.sort(key=lambda row: row["sample_index"])
    assert len(samples) + len(failures) == count
    return samples, failures, {"planned_samples": count, "maximum_inflight_samples": limit,
        "started_unix_seconds": started_unix, "ended_unix_seconds": time.time(),
        "sampling_window_seconds": seconds,
        "attempted_samples": len(samples) + sum(row["attempted"] for row in failures),
        "missed_samples": sum(not row["attempted"] for row in failures),
        "achieved_sample_qps": (len(samples) + sum(row["attempted"] for row in failures)) / seconds}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=ipaddress.ip_address, required=True)
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--seconds", type=int, default=1200)
    parser.add_argument("--qps", type=int, default=1000)
    parser.add_argument("--samples-per-second", type=int, default=10)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 30 <= args.seconds <= 3600:
        parser.error("port or duration outside measurement bounds")
    if not 1 <= args.qps <= 10000 or not 1 <= args.samples_per_second <= 100:
        parser.error("offered rate or sampling rate outside bounds")
    args.output.mkdir(parents=True, exist_ok=True)
    queries = [("example.test.", "SOA"), ("example.test.", "DNSKEY"),
               ("example.test.", "NS"), ("definitely-absent-agentdns.example.test.", "A")]
    query_file = args.output / "dnsperf-queries.txt"
    query_file.write_text("".join(f"{name} {kind}\n" for name, kind in queries))
    log_path = args.output / "dnsperf.log"
    started, started_unix = time.monotonic(), time.time()
    outstanding_load = min(65535, max(100, args.qps * 2))

    def probe(index):
        name, kind = queries[index % len(queries)]
        answer = dns.query.udp(dns.message.make_query(name, kind, want_dnssec=True),
                               str(args.server), port=args.port, timeout=2)
        expected = dns.rcode.NXDOMAIN if name.startswith("definitely-absent-") else dns.rcode.NOERROR
        if not answer.flags & dns.flags.AA or answer.rcode() != expected:
            raise ValueError("unexpected authoritative response")
        return f"{name} {kind}"

    with log_path.open("w") as log:
        load = subprocess.Popen(["dnsperf", "-s", str(args.server), "-p", str(args.port),
                                 "-d", str(query_file), "-l", str(args.seconds), "-Q", str(args.qps),
                                 "-q", str(outstanding_load), "-t", "2", "-D"], stdout=log, stderr=log)
        try:
            samples, failures, sampling = sample_window(probe, args.seconds, args.samples_per_second)
            code = load.wait(timeout=15)
        finally:
            if load.poll() is None:
                load.terminate()
                try:
                    load.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    load.kill()
                    load.wait()
    raw = log_path.read_text()
    metrics = {}
    for label, pattern in [("queries_sent", r"Queries sent:\s+(\d+)"),
                           ("queries_completed", r"Queries completed:\s+(\d+)"),
                           ("queries_lost", r"Queries lost:\s+(\d+)"),
                           ("completed_qps", r"Queries per second:\s+([0-9.]+)")]:
        match = re.search(pattern, raw)
        if match is None:
            raise RuntimeError("dnsperf omitted " + label)
        metrics[label] = float(match[1]) if label == "completed_qps" else int(match[1])
    latencies = sorted(sample["latency_ms"] for sample in samples)
    if code != 0 or not latencies:
        raise RuntimeError("load process failed or no successful latency sample")
    result = {"server": str(args.server), "port": args.port, "dnssec_ok_bit": True,
              "offered_load_qps": args.qps, "offered_sample_qps": args.samples_per_second,
              "started_unix_seconds": started_unix, "ended_unix_seconds": time.time(),
              "elapsed_seconds": time.monotonic() - started, "samples": len(samples),
              "failed_samples": len(failures), "p50_ms": statistics.median(latencies),
              "p99_ms": latencies[max(0, int(len(latencies) * .99) - 1)],
              "maximum_ms": max(latencies), "dnsperf": metrics, "sampling": sampling,
              "load_maximum_outstanding_queries": outstanding_load, "query_timeout_seconds": 2,
              "boundary": "Public DNS only; no registration or governance mutations. External idle delv validates signatures separately. This is a fixed offered load, not maximum capacity."}
    (args.output / "latency-samples.json").write_text(json.dumps(samples, indent=2) + "\n")
    (args.output / "failed-samples.json").write_text(json.dumps(failures, indent=2) + "\n")
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
