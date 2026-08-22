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

import type { Params, ProcessAltNamesParam } from "../../toolbox";
import type { CertificateAuthorityCore } from "./certificate_authority_core";

/**
 * Everything a {@link CertificateAuthorityCore} delegates to a signing backend:
 * the operations that need the CA's private key, or that mutate the CA's
 * certificate database (`index.txt`, `serial`, `crlnumber`,
 * `certs/<SERIAL>.pem`, `crl/revocation_list.*`). Everything else — directory
 * layout, PEM/DER file concatenation, `index.txt` *reading*, URL validation,
 * passphrase handling, `initializeCSR`'s state machine — stays in
 * {@link CertificateAuthorityCore} and is shared by every backend.
 *
 * Two implementations exist. `OpenSslCaBackend` shells out to the `openssl`
 * CLI exactly as `CertificateAuthority` always has, and remains the default.
 * `NativeCaBackend` does the same work in pure JS, which is what allows a
 * CA key held by an HSM or KMS - one that only signs and never exposes key
 * material - to be used at all: the openssl CLI can only load a key from a
 * file. Both write the same on-disk database format, so an install can move
 * between them and external `openssl` tooling keeps working either way.
 */
export interface CaBackend {
    /**
     * Whether this backend can sign with an external {@link CaSigner} - an
     * HSM or KMS key that only signs and never exposes key material.
     * `false` for a backend that can only load a key from a file, so the
     * CA can refuse the combination up front instead of failing later.
     */
    readonly supportsExternalSigner: boolean;

    /**
     * Check whatever this backend needs before it can do any work, and
     * throw if it is missing. `CertificateAuthority` calls it before
     * delegating, so a missing prerequisite is reported once, up front,
     * rather than as a failure part-way through an operation.
     *
     * This exists because the requirement is the backend's, not the CA's:
     * the openssl backend needs the `openssl` executable on PATH, and the
     * native one needs nothing at all. Asking the CA to know that is what
     * made a `backend: "native"` CA refuse to issue a certificate on a
     * machine without openssl installed.
     */
    preflight(): Promise<void>;

    /**
     * Generate the CA's private key (if missing) and its certificate:
     * self-signed for a root CA, signed by `ca._issuerCA` for a subordinate.
     * Also produces the initial CRL. Called once, from
     * {@link CertificateAuthority.initialize}.
     */
    bootstrap(ca: CertificateAuthorityCore): Promise<void>;

    /**
     * Generate a CSR for the CA's own key (`[v3_ca_req]` profile) — used by
     * `initializeCSR`/`renewCSR` when the CA certificate is signed
     * externally.
     */
    generateCaCsr(ca: CertificateAuthorityCore, caRootDir: string, privateKeyFile: string, csrFile: string): Promise<void>;

    /**
     * Sign a subordinate CA's CSR with this CA's key (`[v3_ca]` profile).
     * Used by {@link CertificateAuthority.signCACertificateRequest}.
     */
    signSubordinateCsr(ca: CertificateAuthorityCore, csrFile: string, certFile: string, validityDays: number): Promise<void>;

    /**
     * Sign an end-entity CSR with this CA's key (`[usr_cert]` profile via
     * `openssl ca`) — the certificate database (`index.txt`, `serial`,
     * `certs/<SERIAL>.pem`) is updated as a side effect. Used by
     * {@link CertificateAuthority.signCertificateRequest}.
     *
     * `sanOverride` is the applicationUri/dns/ip the caller already
     * re-derived from the CSR itself (SANs are not copied by `openssl ca`
     * — see the comment at the call site), so the backend can render the
     * `subjectAltName` extension without re-parsing the CSR.
     */
    signEndEntityCsr(
        ca: CertificateAuthorityCore,
        certificate: string,
        csr: string,
        params: Params,
        sanOverride: Required<ProcessAltNamesParam>
    ): Promise<void>;

    /**
     * Mark a certificate revoked in the database and regenerate the CRL.
     * Used by {@link CertificateAuthority.revokeCertificate}.
     */
    revoke(ca: CertificateAuthorityCore, certificate: string, reason: string): Promise<void>;

    /**
     * Regenerate `crl/revocation_list.{crl,der}` from the current database
     * state, without changing any certificate's status. Used after
     * {@link CertificateAuthority.installCACertificate} installs an
     * externally-signed CA certificate.
     */
    regenerateCrl(ca: CertificateAuthorityCore): Promise<void>;

    /**
     * Legacy CLI self-signed certificate creation (`openssl req` +
     * `openssl ca -selfsign`). Used by
     * {@link CertificateAuthority.createSelfSignedCertificate}.
     */
    createSelfSignedCertificate(
        ca: CertificateAuthorityCore,
        certificateFile: string,
        privateKeyFile: string,
        params: Params
    ): Promise<void>;
}
