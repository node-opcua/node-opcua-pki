// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2026 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so,  subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------

import fs from "node:fs";
import path from "node:path";
import { Subject } from "node-opcua-crypto";
import { displaySubtitle, displayTitle, makePath, type Params, type ProcessAltNamesParam } from "../../toolbox";
import {
    buildSubjectAltNameString,
    cleanupStaticConfig,
    ensure_openssl_installed,
    execute_openssl,
    execute_openssl_no_failure,
    generateStaticConfig,
    type OpensslPassArg,
    passinArg,
    setEnv,
    x509Date
} from "../../toolbox/with_openssl";
import type { CaBackend } from "../core/ca_backend";
import type { CertificateAuthorityCore } from "../core/certificate_authority_core";

const n = makePath;

/** The ALTNAME openssl embeds as `subjectAltName` on the CA's own certificate/CSR — see `[v3_ca]` / `[v3_ca_req]`. */
function caAltName(ca: CertificateAuthorityCore): string {
    // OPC UA validators (UaExpert, compliance tools) require every
    // certificate — including the root/intermediate CA — to carry a
    // SubjectAltName extension. RFC 5280 does not strictly mandate it
    // on CA certificates but the OPC UA Profile does. Build a stable
    // URI SAN derived from the CA CommonName so the resulting CA cert
    // passes the spec check.
    return `URI:urn:${ca.subject.commonName || "NodeOPCUA-CA"}`;
}

/**
 * Every render of `conf/caconfig.cnf` needs `ALTNAME` / `CDP_URL` /
 * `AIA_VALUE` resolved, **even for an `openssl` subcommand that only reads
 * a different section** (`ca -gencrl` only needs `[crl_ext]`, `ca -revoke`
 * only needs `[ca]`): openssl's config loader (`NCONF_load`) expands every
 * `$ENV::NAME` reference in the file line by line as it parses it, not
 * lazily per queried section, and every section in this template — not
 * just the two gated behind `{{#CDP_URL}}` / `{{#AIA_VALUE}}` — references
 * `$ENV::ALTNAME` unconditionally. Leaving any of the three unresolved
 * makes openssl fall through to its own native `$ENV::` resolution (a real
 * OS environment variable, which is never set) and fail with "variable has
 * no value".
 *
 * Passed explicitly rather than relying on whatever `setEnv()` last wrote
 * to the shared registry (see {@link generateStaticConfig}'s
 * `envOverrides`) — empty string means "omit the extension" for the two
 * gated keys (the template's `{{#KEY}}` block strips itself on an empty
 * value), never "fall back to the registry".
 *
 * Exported as the single implementation of the CDP/AIA value format:
 * `CertificateAuthority._wireRevocationEnvVars` (the legacy registry shim)
 * delegates here so the format cannot drift between the two mechanisms.
 */
export function caConfigEnvOverrides(ca: CertificateAuthorityCore, altName: string = caAltName(ca)): Record<string, string> {
    const aiaLegs: string[] = [];
    if (ca.ocspResponderUrl) {
        aiaLegs.push(`OCSP;URI:${ca.ocspResponderUrl}`);
    }
    if (ca.caIssuersUrl) {
        aiaLegs.push(`caIssuers;URI:${ca.caIssuersUrl}`);
    }
    return {
        ALTNAME: altName,
        CDP_URL: ca.crlDistributionUrl ?? "",
        AIA_VALUE: aiaLegs.join(",")
    };
}

/**
 * The default {@link CaBackend}: shells out to the `openssl` CLI, exactly as
 * `CertificateAuthority` always has — this is a pure code move (plus a lock
 * around every database-mutating operation, temp-config cleanup, and
 * explicit `envOverrides` on every config render) with no change in the
 * openssl commands issued or the files produced.
 */
export class OpenSslCaBackend implements CaBackend {
    /** This backend is the `openssl` executable, so it has to be there. */
    /**
     * `-passin env:` argv and env for an openssl call that has to load this
     * CA's key. Built here rather than on the CA: the passphrase is the
     * CA's business, but expressing it as an openssl argument is this
     * backend's, and the core has no reason to know the flag exists.
     */
    async #passin(ca: CertificateAuthorityCore): Promise<OpensslPassArg> {
        return passinArg(await ca._privateKeyPassphrase());
    }

    /** The openssl CLI loads its key from a file, so it cannot call out to an HSM. */
    public readonly supportsExternalSigner = false;

    public async preflight(): Promise<void> {
        await ensure_openssl_installed();
    }

    /**
     * Render `conf/caconfig.cnf` once with explicit overrides, run `fn`
     * with the rendered path, and always remove the temp file. Structural
     * guarantee that (a) every render carries the three required env
     * values and (b) no rendered `<name>.<pid>-<n>.tmp` file is ever left
     * behind — each was previously a per-method discipline.
     */
    async #withConfig<T>(
        ca: CertificateAuthorityCore,
        altName: string,
        fn: (configFile: string, options: { cwd: string }) => Promise<T>
    ): Promise<T> {
        const caRootDir = path.resolve(ca.rootDir);
        const options = { cwd: caRootDir };
        const configFile = generateStaticConfig("conf/caconfig.cnf", options, caConfigEnvOverrides(ca, altName));
        try {
            return await fn(configFile, options);
        } finally {
            await cleanupStaticConfig(configFile, options);
        }
    }

    async #generateCaCsrWith(
        ca: CertificateAuthorityCore,
        configFile: string,
        options: { cwd: string },
        privateKeyFile: string,
        csrFile: string
    ): Promise<void> {
        const passin = await this.#passin(ca);
        displayTitle("Generate a certificate request for the CA key");
        await execute_openssl(
            [
                "req",
                "-new",
                "-sha256",
                "-extensions",
                "v3_ca_req",
                "-config",
                n(configFile),
                "-key",
                n(privateKeyFile),
                "-out",
                n(csrFile),
                "-subj",
                ca.subject.toString(),
                ...passin.args
            ],
            { ...options, env: passin.env }
        );
    }

    /**
     * `openssl ca -gencrl` signs the CRL with the CA key it finds through the
     * config file (`private_key = $dir/private/cakey.pem`), so it needs the
     * CA passphrase like every other `openssl ca` invocation.
     */
    async #regenerateCrlWith(ca: CertificateAuthorityCore, configFile: string, options: { cwd: string }): Promise<void> {
        const passin = await this.#passin(ca);
        // produce a CRL in PEM format
        displaySubtitle("regenerate CRL (Certificate Revocation List)");
        await execute_openssl(["ca", "-gencrl", "-config", n(configFile), "-out", "crl/revocation_list.crl", ...passin.args], {
            ...options,
            env: passin.env
        });
        await execute_openssl(
            ["crl", "-in", "crl/revocation_list.crl", "-out", "crl/revocation_list.der", "-outform", "der"],
            options
        );

        displaySubtitle("Display (Certificate Revocation List)");
        await execute_openssl(["crl", "-in", n(ca.revocationList), "-text", "-noout"], options);
    }

    public async generateCaCsr(
        ca: CertificateAuthorityCore,
        _caRootDir: string,
        privateKeyFile: string,
        csrFile: string
    ): Promise<void> {
        await this.#withConfig(ca, caAltName(ca), (configFile, options) =>
            this.#generateCaCsrWith(ca, configFile, options, privateKeyFile, csrFile)
        );
    }

    public async bootstrap(ca: CertificateAuthorityCore): Promise<void> {
        const caRootDir = path.resolve(ca.rootDir);
        const privateKeyFilename = path.join(caRootDir, "private/cakey.pem");
        const csrFilename = path.join(caRootDir, "private/cakey.csr");

        // one render serves the CSR, the CA-certificate signature, and the
        // initial CRL (the overrides are identical for all three)
        await this.#withConfig(ca, caAltName(ca), async (configFile, options) => {
            await this.#generateCaCsrWith(ca, configFile, options, privateKeyFilename, csrFilename);

            const issuerCA = ca._issuerCA;
            if (issuerCA) {
                // Subordinate (intermediate) CA — signed by the parent CA
                displayTitle("Generate CA Certificate (signed by issuer CA)");
                const issuerCert = path.resolve(issuerCA.caCertificate);
                const issuerKey = path.resolve(issuerCA.rootDir, "private/cakey.pem");
                const issuerSerial = path.resolve(issuerCA.rootDir, "serial");
                // the -CAkey is the *issuer's* key: its passphrase, not this CA's
                const issuerPassin = await this.#passin(issuerCA);
                const signWithIssuer = async () => {
                    await execute_openssl(
                        [
                            "x509",
                            "-sha256",
                            "-req",
                            "-days",
                            "3650",
                            "-extensions",
                            "v3_ca",
                            "-extfile",
                            n(configFile),
                            "-in",
                            "private/cakey.csr",
                            "-CA",
                            n(issuerCert),
                            "-CAkey",
                            n(issuerKey),
                            "-CAserial",
                            n(issuerSerial),
                            "-out",
                            "public/cacert.pem",
                            ...issuerPassin.args
                        ],
                        { ...options, env: issuerPassin.env }
                    );
                };
                // `-CAserial` read-increment-writes the ISSUER's serial file,
                // so this must hold the issuer's directory lock, not just the
                // subordinate's (which the caller already holds). The only
                // cross-CA lock ordering in the codebase is subordinate ->
                // issuer, so this cannot deadlock — unless both CAs share one
                // rootDir (a degenerate configuration), where the lock is
                // already held and re-acquiring the non-reentrant file lock
                // would self-deadlock: skip it there.
                if (path.resolve(issuerCA.rootDir) === caRootDir) {
                    await signWithIssuer();
                } else {
                    await issuerCA._withCaDirectoryLock(signWithIssuer);
                }
            } else {
                // Root CA — self-signed
                displayTitle("Generate CA Certificate (self-signed)");
                const passin = await this.#passin(ca);
                await execute_openssl(
                    [
                        "x509",
                        "-sha256",
                        "-req",
                        "-days",
                        "3650",
                        "-extensions",
                        "v3_ca",
                        "-extfile",
                        n(configFile),
                        "-in",
                        "private/cakey.csr",
                        "-signkey",
                        n(privateKeyFilename),
                        "-out",
                        "public/cacert.pem",
                        ...passin.args
                    ],
                    { ...options, env: passin.env }
                );
            }

            displaySubtitle("generate initial CRL (Certificate Revocation List)");
            await this.#regenerateCrlWith(ca, configFile, options);
        });
        displayTitle("Create Certificate Authority (CA) ---> DONE");
    }

    public async regenerateCrl(ca: CertificateAuthorityCore): Promise<void> {
        await this.#withConfig(ca, caAltName(ca), (configFile, options) => this.#regenerateCrlWith(ca, configFile, options));
    }

    public async signSubordinateCsr(
        ca: CertificateAuthorityCore,
        csrFile: string,
        certFile: string,
        validityDays: number
    ): Promise<void> {
        // `[v3_ca]`'s subjectAltName should describe the *subordinate* being
        // certified, not `ca` (the issuer doing the signing) — but nothing
        // here parses `csrFile`'s own subject, so this reuses the issuer's
        // identity as a well-formed placeholder. This is a pre-existing gap,
        // not a regression: the original code left this value to whatever a
        // prior, unrelated operation had last set in the shared env
        // registry (an accidental "URI:undefined" or a stale value from a
        // different CA entirely), so this is deterministic where the
        // original was not, even though neither describes the subordinate.
        await this.#withConfig(ca, caAltName(ca), async (configFile, options) => {
            const caRootDir = options.cwd;
            const passin = await this.#passin(ca);
            await execute_openssl(
                [
                    "x509",
                    "-sha256",
                    "-req",
                    "-days",
                    String(validityDays),
                    "-extensions",
                    "v3_ca",
                    "-extfile",
                    n(configFile),
                    "-in",
                    n(csrFile),
                    "-CA",
                    n(ca.caCertificate),
                    "-CAkey",
                    n(path.join(caRootDir, "private/cakey.pem")),
                    "-CAserial",
                    n(path.join(caRootDir, "serial")),
                    "-out",
                    n(certFile),
                    ...passin.args
                ],
                { ...options, env: passin.env }
            );
        });
    }

    public async signEndEntityCsr(
        ca: CertificateAuthorityCore,
        certificate: string,
        csr: string,
        params1: Params,
        sanOverride: Required<ProcessAltNamesParam>
    ): Promise<void> {
        await this.#withConfig(ca, buildSubjectAltNameString(sanOverride), async (configFile, options) => {
            displaySubtitle("- then we ask the authority to sign the certificate signing request");
            const passin = await this.#passin(ca);
            await execute_openssl(
                [
                    "ca",
                    "-config",
                    configFile,
                    "-startdate",
                    x509Date(params1.startDate),
                    "-enddate",
                    x509Date(params1.endDate),
                    "-batch",
                    "-out",
                    n(certificate),
                    "-in",
                    n(csr),
                    ...passin.args
                ],
                { ...options, env: passin.env }
            );

            displaySubtitle("- dump the certificate for a check");
            await execute_openssl(["x509", "-in", n(certificate), "-dates", "-fingerprint", "-purpose", "-noout"], options);
        });
    }

    public async revoke(ca: CertificateAuthorityCore, certificate: string, reason: string): Promise<void> {
        // one render serves the revocation and the CRL regeneration
        // openssl writes its entropy file here; the native backend has no such notion
        setEnv("RANDFILE", path.join(ca.rootDir, "random.rnd"));
        await this.#withConfig(ca, caAltName(ca), async (configFile, options) => {
            displaySubtitle("Revoke certificate");
            const passin = await this.#passin(ca);
            await execute_openssl_no_failure(
                ["ca", "-verbose", "-config", n(configFile), "-revoke", certificate, "-crl_reason", reason, ...passin.args],
                { ...options, env: passin.env }
            );

            // regenerate CRL (Certificate Revocation List)
            await this.#regenerateCrlWith(ca, configFile, options);

            displaySubtitle("Verify that certificate is revoked");
            await execute_openssl_no_failure(
                [
                    "verify",
                    "-verbose",
                    "-CRLfile",
                    n(ca.revocationList),
                    "-CAfile",
                    n(ca.caCertificate),
                    "-crl_check",
                    n(certificate)
                ],
                options
            );

            // produce CRL in DER format
            displaySubtitle("Produce CRL in DER form ");
            await execute_openssl(
                ["crl", "-in", n(ca.revocationList), "-out", "crl/revocation_list.der", "-outform", "der"],
                options
            );
            // produce CRL in PEM format with text
            displaySubtitle("Produce CRL in PEM form ");
            await execute_openssl(
                ["crl", "-in", n(ca.revocationList), "-out", "crl/revocation_list.pem", "-outform", "pem", "-text"],
                options
            );
        });
    }

    public async createSelfSignedCertificate(
        ca: CertificateAuthorityCore,
        certificateFile: string,
        privateKeyFile: string,
        params: Params
    ): Promise<void> {
        // Explicit overrides like every other method: `$ENV::ALTNAME` in the
        // rendered config comes from THIS call's params, never from whatever
        // the shared env registry happened to hold — the registry-based
        // render made a concurrent operation's SANs (or an empty ALTNAME
        // from a concurrent revoke) leak into this certificate. CDP/AIA now
        // deterministically follow this CA's configured URLs as well.
        const envOverrides = caConfigEnvOverrides(ca, buildSubjectAltNameString(params));
        const configFile = generateStaticConfig(ca.configFile, { cwd: ca.rootDir }, envOverrides);
        const options = {
            cwd: ca.rootDir,
            openssl_conf: makePath(configFile)
        };

        try {
            const subject = params.subject ? new Subject(params.subject).toString() : "";
            const subjectOptions = subject && subject.length > 1 ? ["-subj", subject] : [];
            const csrFile = `${certificateFile}_csr`;

            // `req -new -key` reads (and, for an encrypted key, must decrypt)
            // privateKeyFile too: without -passin it hangs indefinitely
            // waiting on a passphrase prompt that never comes, even with
            // stdin redirected to /dev/null — unlike e.g. `pkcs12`/`rsa
            // -pubout`, which fail fast instead. Reproduced directly against
            // OpenSSL 3.5.4. Empty passin is a no-op against a plaintext key.
            const passin = await this.#passin(ca);

            displaySubtitle("- the certificate signing request");
            await execute_openssl(
                [
                    "req",
                    "-new",
                    "-sha256",
                    ...subjectOptions,
                    "-batch",
                    "-key",
                    n(privateKeyFile),
                    "-out",
                    n(csrFile),
                    ...passin.args
                ],
                { ...options, env: passin.env }
            );

            displaySubtitle("- creating the self-signed certificate");
            await execute_openssl(
                [
                    "ca",
                    "-selfsign",
                    "-keyfile",
                    n(privateKeyFile),
                    "-startdate",
                    x509Date(params.startDate),
                    "-enddate",
                    x509Date(params.endDate),
                    "-batch",
                    "-out",
                    n(certificateFile),
                    "-in",
                    n(csrFile),
                    ...passin.args
                ],
                { ...options, env: passin.env }
            );

            displaySubtitle("- dump the certificate for a check");
            await execute_openssl(["x509", "-in", n(certificateFile), "-dates", "-fingerprint", "-purpose", "-noout"], {});

            displaySubtitle("- verify self-signed certificate");
            await execute_openssl_no_failure(["verify", "-verbose", "-CAfile", n(certificateFile), n(certificateFile)], options);

            await fs.promises.unlink(csrFile);
        } finally {
            await cleanupStaticConfig(configFile, { cwd: ca.rootDir });
        }
    }
}
