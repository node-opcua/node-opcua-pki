import fs from "node:fs";
import path from "node:path";
import "should";
import { NativeCaBackend } from "node-opcua-pki-priv/ca/backends/native_ca_backend";
import { OpenSslCaBackend } from "node-opcua-pki-priv/ca/backends/openssl_ca_backend";

const libDir = path.join(__dirname, "../packages/node-opcua-pki/lib");

/**
 * The module specifiers `file` imports for their *values*.
 *
 * `import type { X } from "y"` is skipped: it disappears at compile time and
 * so cannot pull anything into a bundle. Inline `{ type X }` inside an
 * otherwise-value import is deliberately still counted - that is the
 * conservative direction for a boundary check, which should complain too
 * eagerly rather than miss a real edge.
 */
function valueImportsOf(file: string): string[] {
    const source = fs.readFileSync(file, "utf-8");
    const specifiers: string[] = [];
    const importRe = /import\s+(type\s+)?[^;]*?from\s+"([^"]+)"/g;
    for (const match of source.matchAll(importRe)) {
        if (match[1]) {
            continue; // `import type ... from` erases
        }
        specifiers.push(match[2]);
    }
    return specifiers;
}

/** Resolve a relative specifier to the .ts file it names, directory barrels included. */
function resolveLocal(fromFile: string, specifier: string): string | undefined {
    if (!specifier.startsWith(".")) {
        return undefined; // a package, not our source
    }
    const base = path.resolve(path.dirname(fromFile), specifier);
    for (const candidate of [`${base}.ts`, path.join(base, "index.ts")]) {
        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }
    return undefined;
}

/** Every local module reachable from `entry` by following value imports. */
function reachableFrom(entry: string): Set<string> {
    const seen = new Set<string>();
    const queue = [entry];
    while (queue.length > 0) {
        const file = queue.pop() as string;
        if (seen.has(file)) {
            continue;
        }
        seen.add(file);
        for (const specifier of valueImportsOf(file)) {
            const resolved = resolveLocal(file, specifier);
            if (resolved) {
                queue.push(resolved);
            }
        }
    }
    return seen;
}

function relative(files: Iterable<string>): string[] {
    return [...files].map((f) => path.relative(libDir, f).replace(/\\/g, "/"));
}

// The native backend exists so a CA can run without the openssl executable.
// That claim is not provable by running the test suite, because openssl is
// installed on every machine the suite runs on - so it is checked here at the
// import graph instead, where it either holds or it does not.
describe("import boundaries", () => {
    const opensslModules = /toolbox\/with_openssl/;

    it("the PFX toolbox reaches no openssl module", () => {
        // toolbox_pfx used to spawn `openssl pkcs12` and so counted as an
        // openssl module itself. It is now pure JS, which is only true for
        // as long as nothing re-introduces an import - and unlike the
        // bundling, that would not show up in any behavioural test, since
        // openssl is installed wherever this suite runs.
        const reached = relative(reachableFrom(path.join(libDir, "pki/toolbox_pfx.ts")));
        const offenders = reached.filter((f) => opensslModules.test(f));
        offenders.should.eql([], `toolbox_pfx must not reach openssl, but reaches:\n  ${offenders.join("\n  ")}`);
    });

    it("the native backend reaches no openssl module", () => {
        const reached = relative(reachableFrom(path.join(libDir, "ca/backends/native_ca_backend.ts")));
        const offenders = reached.filter((f) => opensslModules.test(f));
        offenders.should.eql([], `native_ca_backend must not reach openssl, but reaches:\n  ${offenders.join("\n  ")}`);
    });

    it("nothing in ca/core reaches an openssl module", () => {
        // ca/core exists so a program can build a CA around its own backend
        // without dragging openssl in. The rule belongs to the folder, not to
        // any one file in it: every module is checked, so a file added later
        // is covered without anyone remembering to extend this test.
        const coreDir = path.join(libDir, "ca/core");
        const entries = fs.readdirSync(coreDir).filter((f) => f.endsWith(".ts"));
        entries.length.should.be.greaterThan(0, "ca/core should contain modules");

        const offenders: string[] = [];
        for (const entry of entries) {
            for (const reached of relative(reachableFrom(path.join(coreDir, entry)))) {
                if (opensslModules.test(reached)) {
                    offenders.push(`${entry} -> ${reached}`);
                }
            }
        }
        offenders.should.eql([], `ca/core must not reach openssl, but:\n  ${offenders.join("\n  ")}`);
    });

    it("the ./core entry point reaches no openssl module", () => {
        // lib/core.ts is what `node-opcua-pki/core` resolves to and is built
        // as its own bundle. If anything it exports reached openssl, the
        // subpath would quietly ship the very thing it exists to leave out.
        const reached = relative(reachableFrom(path.join(libDir, "core.ts")));
        const offenders = reached.filter((f) => opensslModules.test(f));
        offenders.should.eql([], `the ./core entry must not reach openssl, but reaches:\n  ${offenders.join("\n  ")}`);
    });

    it("CertificateAuthority does reach openssl, being the subclass that picks it", () => {
        const reached = relative(reachableFrom(path.join(libDir, "ca/certificate_authority.ts")));
        reached.filter((f) => opensslModules.test(f)).length.should.be.greaterThan(0);
    });

    it("the openssl backend does reach them, so the check above cannot pass vacuously", () => {
        const reached = relative(reachableFrom(path.join(libDir, "ca/backends/openssl_ca_backend.ts")));
        reached.filter((f) => opensslModules.test(f)).length.should.be.greaterThan(0);
    });

    it("preflight belongs to the backend: openssl requires its executable, native requires nothing", async () => {
        // signCertificateRequest used to call ensure_openssl_installed()
        // itself, so a `backend: "native"` CA refused to issue a certificate
        // on a machine with no openssl - the one thing the native backend is
        // supposed to make possible.
        await new NativeCaBackend().preflight().should.be.fulfilled();

        const opensslPreflight = new OpenSslCaBackend().preflight();
        await opensslPreflight.should.be.fulfilled(); // openssl is installed here
    });
});
