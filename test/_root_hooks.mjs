// Root hook: turn "the suite passed but the process never exits" into a fast, named
// failure.
//
// This exists because of a real bug that cost a long debugging session. The suite printed
// "250 passing" and then sat for 300s before dying with ERR_MOCHA_MULTIPLE_DONE, because
// a test called beforeTest() from inside a `before` hook - registering a mocha hook after
// the suite tree was built, which armed a 5-minute timeout that was never cleared.
//
// Nothing failed. The suite was green. It just hung, which on CI reads as a stuck job
// rather than a test failure.
//
// Two implementation notes, both learned the hard way:
//
//   1. Use getActiveResourcesInfo(), NOT _getActiveHandles(). The latter does not report
//      timers - they live in a separate internal list - so it reports zero active handles
//      while the process is plainly stuck. That sent the original investigation down the
//      wrong path entirely.
//
//   2. Do not `throw` from here. mocha invokes mochaGlobalTeardown but swallows anything
//      it throws once the run has completed: the message never appears and the process
//      hangs anyway. We print and force-exit instead, which is also what makes CI fail in
//      seconds rather than sitting until the job timeout.

// Allow-list of resources that actually indicate a leak, rather than a deny-list of
// benign ones. stdio alone shows up as PipeWrap/TTYWrap/FileHandle depending on whether
// output is piped, redirected or a terminal, so a deny-list false-positives on CI - where
// output is always piped. These are the kinds that have genuinely blocked exit here.
const SUSPICIOUS = new Set([
    "Timeout", // the mocha-hook bug above
    "Immediate",
    "FSEvent", // chokidar / fs.watch - an undisposed CertificateManager
    "FSWatcher",
    "StatWatcher", // polling watchers
    "ChildProcess", // a stray openssl invocation
    "TCPSocketWrap",
    "TCPServerWrap",
    "Socket",
    "Server"
]);

/** Concrete detail per handle, so the failure names the culprit and not just its type. */
function describeHandles() {
    const out = [];
    for (const h of process._getActiveHandles?.() ?? []) {
        const name = h?.constructor?.name ?? typeof h;
        if (name === "StatWatcher" || name === "FSEvent" || name === "FSWatcher") {
            out.push(`${name} path=${h._filename ?? h.path ?? "?"}`);
        } else if (name === "ChildProcess") {
            out.push(`${name} pid=${h.pid} file=${h.spawnfile}`);
        } else if (name === "Socket" || name === "Server") {
            out.push(`${name} remote=${h.remoteAddress ?? "-"}:${h.remotePort ?? "-"}`);
        }
    }
    return out;
}

// How long to let the event loop drain before calling it a leak. A point-in-time check
// right after the last test is far too eager: a clean run legitimately still has ~10
// short-lived timers in flight (polling helpers, chokidar internals) that fire and clear
// within a second or so. What distinguishes a leak is that it NEVER drains - the bug this
// guards against left a 300s timer armed - so we wait for drain and only report if the
// deadline passes.
const DRAIN_DEADLINE_MS = 15_000;
const DRAIN_POLL_MS = 250;

export async function mochaGlobalTeardown() {
    const deadline = Date.now() + DRAIN_DEADLINE_MS;
    let leaked = [];

    for (;;) {
        await new Promise((resolve) => setTimeout(resolve, DRAIN_POLL_MS));
        leaked = process.getActiveResourcesInfo().filter((kind) => SUSPICIOUS.has(kind));
        if (leaked.length === 0) {
            return; // drained - the process will exit on its own
        }
        if (Date.now() >= deadline) {
            break; // still held after the grace period: a real leak
        }
    }

    const tally = {};
    for (const kind of leaked) {
        tally[kind] = (tally[kind] ?? 0) + 1;
    }
    const summary = Object.entries(tally)
        .sort((a, b) => b[1] - a[1])
        .map(([kind, n]) => `${n}x ${kind}`)
        .join(", ");
    const detail = describeHandles();

    console.error("");
    console.error("──────────────────────────────────────────────────────────────────");
    console.error(` LEAKED RESOURCES: the suite passed but ${leaked.length} resource(s) are still`);
    console.error(" holding the event loop open after 15s, so the process would hang forever.");
    console.error("");
    console.error(`   ${summary}`);
    if (detail.length) {
        for (const d of detail) {
            console.error(`   ${d}`);
        }
    }
    console.error("");
    console.error(" Usual causes:");
    console.error("   - a CertificateManager never dispose()d (it starts chokidar watchers)");
    console.error("   - beforeTest() called from inside a before hook rather than the");
    console.error("     describe body, which registers a mocha hook after the suite tree is");
    console.error("     built and leaves its timeout armed forever");
    console.error("   - a child process or socket a test never closed");
    console.error("──────────────────────────────────────────────────────────────────");
    console.error("");

    // Force the exit: the whole point is that the loop will not drain on its own.
    process.exit(1);
}
