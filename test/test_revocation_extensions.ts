// ---------------------------------------------------------------------------
// US-202 — Optional CDP and AIA extensions in issued certificates
//
// Covers:
//   - validation rules on setCrlDistributionUrl / setOcspResponderUrl /
//     setCaIssuersUrl (throws on garbage, accepts undefined, warns on
//     loopback).
//   - the conditional emission of crlDistributionPoints and
//     authorityInfoAccess in end-entity certs signed by signCertificateRequest:
//       * neither set    → both extensions absent
//       * CDP set        → CDP present, AIA absent
//       * OCSP set       → AIA OCSP leg present, no CDP, no caIssuers leg
//       * caIssuers set  → AIA caIssuers leg present, no CDP, no OCSP leg
//       * OCSP + caIss   → both AIA legs present, no CDP
//       * all three set  → all three lines present, OCSP leg first
//
// Verification uses `openssl x509 -text -noout` so we read the cert
// exactly the way every relying party will.
// ---------------------------------------------------------------------------

import fs from "node:fs";
import path from "node:path";
import { CertificateAuthority, type CertificateAuthorityOptions, CertificateManager, type Filename } from "node-opcua-pki";
import { execute_openssl } from "node-opcua-pki-priv/toolbox/with_openssl";
import should from "should";

import { beforeTest } from "./helpers";

async function buildCsr(tmpFolder: string, applicationUri: string): Promise<{ csr: Filename; certOut: Filename }> {
    const pkiFolder = path.join(tmpFolder, `client-${Date.now()}-${Math.floor(Math.random() * 1e9)}`);
    const cm = new CertificateManager({ location: pkiFolder, keySize: 2048 });
    await cm.initialize();
    await cm.createCertificateRequest({
        applicationUri,
        subject: "/CN=test-app",
        dns: ["test.example.com"],
        startDate: new Date(),
        validity: 365
    });
    // CertificateManager writes the CSR to a deterministic name —
    // discover it under its own_certificate folder.
    const ownDir = path.join(pkiFolder, "own");
    const certsDir = path.join(ownDir, "certs");
    const files = await fs.promises.readdir(certsDir);
    const csrFile = files.find((f) => f.endsWith(".csr"));
    if (!csrFile) {
        throw new Error(`could not find CSR in ${certsDir}: ${files.join(", ")}`);
    }
    return {
        csr: path.join(certsDir, csrFile),
        certOut: path.join(tmpFolder, `signed-${Date.now()}-${Math.floor(Math.random() * 1e9)}.pem`)
    };
}

async function dumpCertText(certPath: Filename): Promise<string> {
    return await execute_openssl(["x509", "-text", "-noout", "-in", certPath], { cwd: path.dirname(certPath) });
}

describe("US-202 — Optional CDP & AIA extensions", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    describe("Setter validation", () => {
        const ca = new CertificateAuthority({
            keySize: 2048,
            location: path.join(__dirname, "../tmp/CA_us202_validate")
        });

        it("AC-1 — undefined leaves the extension disabled (getter returns undefined)", () => {
            ca.setCrlDistributionUrl(undefined);
            should(ca.crlDistributionUrl).be.undefined();
            ca.setOcspResponderUrl(undefined);
            should(ca.ocspResponderUrl).be.undefined();
            ca.setCaIssuersUrl(undefined);
            should(ca.caIssuersUrl).be.undefined();
        });

        it("AC-3 — empty string throws with a 'pass undefined' hint", () => {
            (() => ca.setCrlDistributionUrl("")).should.throw(/pass undefined/);
            (() => ca.setOcspResponderUrl("")).should.throw(/pass undefined/);
            (() => ca.setCaIssuersUrl("")).should.throw(/pass undefined/);
        });

        it("AC-4 — non-URL strings throw", () => {
            (() => ca.setCrlDistributionUrl("not-a-url")).should.throw(/not a valid URL/);
        });

        it("AC-4 — non-http(s) protocols throw", () => {
            (() => ca.setCrlDistributionUrl("ftp://pki.example.com/crl.pem")).should.throw(/http: or https:/);
            (() => ca.setOcspResponderUrl("ldap://pki.example.com/ocsp")).should.throw(/http: or https:/);
        });

        it("AC-4 — URL without a path throws", () => {
            (() => ca.setCrlDistributionUrl("https://pki.example.com")).should.throw(/path component/);
            (() => ca.setCrlDistributionUrl("https://pki.example.com/")).should.throw(/path component/);
        });

        it("AC-2/AC-5 — valid http and https URLs are accepted; loopback only warns", () => {
            ca.setCrlDistributionUrl("https://pki.example.com/crl.der");
            should(ca.crlDistributionUrl).eql("https://pki.example.com/crl.der");

            // loopback — must not throw
            const originalWarn = console.warn;
            const warnings: string[] = [];
            console.warn = (...args: unknown[]) => {
                warnings.push(args.map((a) => String(a)).join(" "));
            };
            try {
                ca.setCrlDistributionUrl("http://localhost:9100/crl.der");
                should(ca.crlDistributionUrl).eql("http://localhost:9100/crl.der");
            } finally {
                console.warn = originalWarn;
            }
            warnings.some((w) => /loopback/.test(w)).should.be.true();
        });

        it("setters round-trip on the constructor option fields", () => {
            const ca2 = new CertificateAuthority({
                keySize: 2048,
                location: path.join(__dirname, "../tmp/CA_us202_options_roundtrip"),
                crlDistributionUrl: "https://pki.example.com/crl.der",
                ocspResponderUrl: "https://pki.example.com/ocsp",
                caIssuersUrl: "https://pki.example.com/ca.der"
            });
            should(ca2.crlDistributionUrl).eql("https://pki.example.com/crl.der");
            should(ca2.ocspResponderUrl).eql("https://pki.example.com/ocsp");
            should(ca2.caIssuersUrl).eql("https://pki.example.com/ca.der");
        });

        it("constructor rejects an invalid CDP URL synchronously", () => {
            (() =>
                new CertificateAuthority({
                    keySize: 2048,
                    location: path.join(__dirname, "../tmp/CA_us202_options_invalid"),
                    crlDistributionUrl: "not-a-url"
                })).should.throw(/not a valid URL/);
        });
    });

    describe("Extension emission in signed end-entity certs", () => {
        // One CA per scenario keeps the assertions hermetic.
        async function signEndEntity(
            caLocation: string,
            urls: {
                crlDistributionUrl?: string;
                ocspResponderUrl?: string;
                caIssuersUrl?: string;
            },
            applicationUri: string
        ): Promise<string> {
            const opts: CertificateAuthorityOptions = {
                keySize: 2048,
                location: caLocation,
                ...urls
            };
            const ca = new CertificateAuthority(opts);
            await ca.initialize();

            const { csr, certOut } = await buildCsr(testData.tmpFolder, applicationUri);
            await ca.signCertificateRequest(certOut, csr, {
                applicationUri,
                dns: ["test.example.com"],
                ip: [],
                startDate: new Date(),
                validity: 365
            } as never);
            return await dumpCertText(certOut);
        }

        it("AC-1 — no URLs configured: neither extension appears in issued cert", async () => {
            const text = await signEndEntity(path.join(testData.tmpFolder, "CA_us202_none"), {}, "urn:test:none");
            text.should.not.match(/X509v3 CRL Distribution Points/);
            text.should.not.match(/Authority Information Access/);
        });

        it("AC-2 — only CDP set: CRL Distribution Points present, AIA absent", async () => {
            const text = await signEndEntity(
                path.join(testData.tmpFolder, "CA_us202_cdp"),
                { crlDistributionUrl: "http://pki.example.com:9100/crl.der" },
                "urn:test:cdp"
            );
            text.should.match(/X509v3 CRL Distribution Points/);
            text.should.match(/URI:http:\/\/pki\.example\.com:9100\/crl\.der/);
            text.should.not.match(/Authority Information Access/);
        });

        it("AC-7 — only OCSP set: AIA OCSP leg present, no caIssuers leg, no CDP", async () => {
            const text = await signEndEntity(
                path.join(testData.tmpFolder, "CA_us202_ocsp"),
                { ocspResponderUrl: "http://pki.example.com:9100/ocsp" },
                "urn:test:ocsp"
            );
            text.should.match(/Authority Information Access/);
            text.should.match(/OCSP - URI:http:\/\/pki\.example\.com:9100\/ocsp/);
            text.should.not.match(/CA Issuers/);
            text.should.not.match(/X509v3 CRL Distribution Points/);
        });

        it("only caIssuers set: AIA caIssuers leg present, no OCSP leg", async () => {
            const text = await signEndEntity(
                path.join(testData.tmpFolder, "CA_us202_caissuers"),
                { caIssuersUrl: "http://pki.example.com:9100/ca.der" },
                "urn:test:caissuers"
            );
            text.should.match(/Authority Information Access/);
            text.should.match(/CA Issuers - URI:http:\/\/pki\.example\.com:9100\/ca\.der/);
            text.should.not.match(/OCSP - URI:/);
            text.should.not.match(/X509v3 CRL Distribution Points/);
        });

        it("AC-6 — OCSP + caIssuers set: AIA carries both legs", async () => {
            const text = await signEndEntity(
                path.join(testData.tmpFolder, "CA_us202_both_aia"),
                {
                    ocspResponderUrl: "http://pki.example.com:9100/ocsp",
                    caIssuersUrl: "http://pki.example.com:9100/ca.der"
                },
                "urn:test:both-aia"
            );
            text.should.match(/Authority Information Access/);
            text.should.match(/OCSP - URI:http:\/\/pki\.example\.com:9100\/ocsp/);
            text.should.match(/CA Issuers - URI:http:\/\/pki\.example\.com:9100\/ca\.der/);
            text.should.not.match(/X509v3 CRL Distribution Points/);
        });

        it("AC-2/AC-6 — all three URLs set: CDP and full AIA both present", async () => {
            const text = await signEndEntity(
                path.join(testData.tmpFolder, "CA_us202_all"),
                {
                    crlDistributionUrl: "http://pki.example.com:9100/crl.der",
                    ocspResponderUrl: "http://pki.example.com:9100/ocsp",
                    caIssuersUrl: "http://pki.example.com:9100/ca.der"
                },
                "urn:test:all"
            );
            text.should.match(/X509v3 CRL Distribution Points/);
            text.should.match(/URI:http:\/\/pki\.example\.com:9100\/crl\.der/);
            text.should.match(/Authority Information Access/);
            text.should.match(/OCSP - URI:http:\/\/pki\.example\.com:9100\/ocsp/);
            text.should.match(/CA Issuers - URI:http:\/\/pki\.example\.com:9100\/ca\.der/);
        });
    });
});
