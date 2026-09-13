#!/usr/bin/env python3
"""Bounded /proc RSS and cgroup-v2 memory observation inside the BIND container."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import time


def process_status(raw):
    values = {}
    for name in ("VmRSS", "VmHWM"):
        match = re.search(r"^" + name + r":\s+(\d+)\s+kB$", raw, re.MULTILINE)
        if match is None:
            raise ValueError("process RSS counters unavailable")
        values[name] = int(match[1])
    name = re.search(r"^Name:\s+(.+)$", raw, re.MULTILINE)
    if name is None or name[1] != "named":
        raise ValueError("PID1 is not the expected named process")
    return {"rss_kib": values["VmRSS"], "high_water_rss_kib": values["VmHWM"], "comm": name[1]}


def counter(path):
    value = path.read_text().strip()
    if not value.isascii() or not value.isdecimal():
        raise ValueError("noninteger memory counter")
    return int(value)


def process_start(raw):
    # /proc stat comm may contain spaces; field22 is offset19 after its final ')'.
    fields = raw.rsplit(")", 1)[1].split()
    return int(fields[19])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=1200)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 30 <= args.seconds <= 1250 or args.seconds % 10:
        parser.error("duration must be a multiple of 10 within30..1250 seconds")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    proc = Path("/proc/1")
    identity = process_start((proc / "stat").read_text())
    process_status((proc / "status").read_text())
    cgroup = Path("/sys/fs/cgroup")
    # Require a container-root cgroup namespace so counters cannot describe the VM.
    group_text = (proc / "cgroup").read_text()
    cgroup_available = group_text.strip() == "0::/" and (cgroup / "memory.current").is_file()
    started, started_unix, cpu_started = time.monotonic(), time.time(), time.process_time()
    samples = []
    metadata = {
        "pid_in_target_container": 1, "process_start_clock_ticks": identity,
        "started_unix_seconds": started_unix, "requested_seconds": args.seconds,
        "cgroup_v2_available": cgroup_available, "process_cgroup": group_text.strip(),
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "rss_units": "KiB (Linux /proc kB =1024 bytes)",
        "cgroup_units": "bytes; aggregate named+collector+other container allocations including cache",
        "scope": "Actual named PID1 VmRSS/VmHWM; cgroup aggregate is a separate metric, not RSS. Collector runs inside this measured container. No leak-freedom claim.",
    }
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    for index in range(args.seconds // 10 + 1):
        target = started + index * 10
        time.sleep(max(0, target - time.monotonic()))
        began = time.monotonic()
        if began - started > args.seconds + 15:
            raise TimeoutError("collector exceeded bounded sampling window")
        if process_start((proc / "stat").read_text()) != identity:
            raise RuntimeError("named process identity changed")
        sample = {"index": index, "unix_seconds": time.time(), "elapsed_seconds": began - started,
                  **process_status((proc / "status").read_text())}
        if cgroup_available:
            sample["cgroup_memory_current_bytes"] = counter(cgroup / "memory.current")
            peak = cgroup / "memory.peak"
            sample["cgroup_memory_peak_bytes"] = counter(peak) if peak.is_file() else None
            sample["cgroup_memory_events"] = dict(
                (key, int(value)) for key, value in
                (line.split() for line in (cgroup / "memory.events").read_text().splitlines())
            )
        sample["counter_read_elapsed_seconds"] = time.monotonic() - began
        samples.append(sample)
        temporary = args.output / "samples.tmp"
        temporary.write_text(json.dumps(samples, separators=(",", ":")) + "\n")
        temporary.replace(args.output / "samples.json")
    result = {
        **metadata, "ended_unix_seconds": time.time(), "elapsed_seconds": time.monotonic() - started,
        "sample_count": len(samples), "minimum_rss_kib": min(s["rss_kib"] for s in samples),
        "maximum_rss_kib": max(s["rss_kib"] for s in samples),
        "first_rss_kib": samples[0]["rss_kib"], "last_rss_kib": samples[-1]["rss_kib"],
        "collector_cpu_seconds": time.process_time() - cpu_started,
        "collector_maximum_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "maximum_counter_read_seconds": max(s["counter_read_elapsed_seconds"] for s in samples),
    }
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
