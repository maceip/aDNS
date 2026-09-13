# Python OpenTelemetry and transport regressions

Twenty-nine focused tests passed on actual Linux/Python 3.12.14 in the pinned local Azure Linux CCF toolchain image. The tests used real ephemeral local HTTP, HTTPS and Unix sockets and decoded actual SDK-generated OTLP protobuf. They exercised authenticated TLS/custom CA, wrong-name/trust rejection, resource/ID/link preservation, input/header/attribute bounds, secret exclusion, queue saturation, finite shutdown, slow headers, the unchanged commit gate and explicit cross-thread context.

The NOTIFY→AXFR→SOA→next-signing link test uses a fake committed CCF gate and unchanged test DNS packets; it establishes diagnostic correlation behavior, not actual TSIG or hardware execution. This source postdates the completed native acceptance deployment. Instrumented CCF/collector integration must be established separately.

Six exact source/documentation/dependency files were copied before the run, mounted read-only and rechecked afterward. Dependencies were installed from the pinned requirements into a disposable container `/tmp` directory. The transient test container was removed. Only public code, synthetic test inputs, dependency logs and result metadata are exported; ephemeral TLS private keys remained inside temporary test storage and were deleted.

See [summary.json](summary.json), [tests.log](tests.log), and [the frozen tracing contract](source/ccf/TELEMETRY.md).
