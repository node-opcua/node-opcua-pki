import path from "node:path";
import should from "should";
import { safeStoreJoin, toFilenameLabel } from "../packages/node-opcua-pki/lib/pki/certificate_manager";

// GHSA-m7pm-7jm9-cfp4 — Path Traversal in PKI certificate storage.
//
// A stored certificate's on-disk filename is derived from its Common Name. If
// the CN keeps the path separators "/" and "\", a CN of "../trusted/certs/pwned"
// makes path.join() climb out of rejected/ and land the certificate in the
// trusted store — an unauthenticated trust-store-poisoning primitive.
//
// Two independent layers must hold:
//   1. toFilenameLabel() strips the separators from the CN (naming layer).
//   2. safeStoreJoin() refuses any resolved path that escapes its store folder
//      (containment backstop), regardless of the sanitizer.

// The traversal payloads a malicious certificate CN could carry.
const traversalCommonNames = [
    "../trusted/certs/pwned",
    "..\\trusted\\certs\\pwned",
    "../../../../etc/opcua/trusted/certs/pwned",
    "a/../../trusted/certs/pwned",
    "/etc/passwd"
];

describe("GHSA-m7pm-7jm9-cfp4 — CN path traversal is contained", () => {
    describe("naming layer: toFilenameLabel strips separators", () => {
        for (const commonName of traversalCommonNames) {
            it(`neutralises ${JSON.stringify(commonName)}`, () => {
                const label = toFilenameLabel(commonName);
                should(label.includes("/")).eql(false, `label must not contain "/" -> ${JSON.stringify(label)}`);
                should(label.includes("\\")).eql(false, `label must not contain "\\" -> ${JSON.stringify(label)}`);

                // Joining the sanitised label under a store folder stays inside it.
                const rejected = path.resolve("/pki/rejected");
                const full = path.resolve(rejected, `${label}.pem`);
                should(full.startsWith(rejected + path.sep)).eql(true, `write must stay in rejected/ -> ${full}`);
            });
        }
    });

    describe("containment backstop: safeStoreJoin", () => {
        const folder = path.resolve("/pki/rejected");

        it("returns the joined path for an ordinary <label>.pem filename", () => {
            const expected = path.resolve(folder, "MyDevice-01[ABCDEF0123].pem");
            should(safeStoreJoin(folder, "MyDevice-01[ABCDEF0123].pem")).eql(expected);
        });

        it("throws when a filename would escape the store folder", () => {
            // Even if the naming layer ever regressed and let separators through,
            // the backstop must refuse the write rather than poison trusted/.
            should(() => safeStoreJoin(folder, "../trusted/certs/pwned[ABCDEF0123].pem")).throw(/escapes its store folder/);
        });

        it("throws for a Windows-separator escape too", () => {
            should(() => safeStoreJoin(folder, "..\\trusted\\certs\\pwned.pem")).throw(/escapes its store folder/);
        });

        it("throws for an absolute-path filename", () => {
            const abs = process.platform === "win32" ? "C:\\Windows\\Temp\\x.pem" : "/tmp/x.pem";
            should(() => safeStoreJoin(folder, abs)).throw(/escapes its store folder/);
        });
    });
});
