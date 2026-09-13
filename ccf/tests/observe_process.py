#!/usr/bin/env python3
"""Record Linux process RSS through an explicitly shared test PID namespace."""
import argparse
import json
import pathlib
import re
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, default=1)
    parser.add_argument("--name", required=True)
    parser.add_argument("--seconds", type=int, default=1200)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.pid or not 30 <= args.seconds <= 3600:
        parser.error("PID or duration outside bounds")
    args.output.mkdir(parents=True, exist_ok=True)
    start, start_unix = time.monotonic(), time.time()
    samples = []
    while True:
        raw = pathlib.Path(f"/proc/{args.pid}/status").read_text()
        rss = re.search(r"^VmRSS:\s+(\d+)\s+kB$", raw, re.MULTILINE)
        high = re.search(r"^VmHWM:\s+(\d+)\s+kB$", raw, re.MULTILINE)
        comm = re.search(r"^Name:\s+(.+)$", raw, re.MULTILINE)
        if rss is None or high is None or comm is None:
            raise RuntimeError("process exited or RSS counters unavailable")
        samples.append({"unix_seconds": time.time(), "elapsed_seconds": time.monotonic() - start,
                        "rss_kib": int(rss[1]), "high_water_rss_kib": int(high[1]), "comm": comm[1]})
        path = args.output / (args.name + "-samples.json")
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(samples, indent=2) + "\n")
        temporary.replace(path)
        if time.monotonic() - start >= args.seconds:
            break
        time.sleep(min(10, max(0, args.seconds - (time.monotonic() - start))))
    result = {"process": args.name, "pid_in_target_container": args.pid,
              "started_unix_seconds": start_unix, "ended_unix_seconds": time.time(),
              "elapsed_seconds": time.monotonic() - start, "samples": len(samples),
              "minimum_rss_kib": min(s["rss_kib"] for s in samples),
              "maximum_rss_kib": max(s["rss_kib"] for s in samples),
              "first_rss_kib": samples[0]["rss_kib"], "last_rss_kib": samples[-1]["rss_kib"],
              "scope": "Linux /proc RSS for one actual process; excludes other processes and does not establish absence of leaks."}
    (args.output / (args.name + "-results.json")).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
