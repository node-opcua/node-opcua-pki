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
import assert from "node:assert";

/** RSA key size in bits. */
export type KeySize = 1024 | 2048 | 3072 | 4096;
/** Hex-encoded SHA-1 certificate thumbprint. */
export type Thumbprint = string;
/** A filesystem path to a file. */
export type Filename = string;
/** Status of a certificate in the trust store. */
export type CertificateStatus = "unknown" | "trusted" | "rejected";

import type { CertificatePurpose, PrivateKey } from "node-opcua-crypto";
import type { SubjectOptions } from "../misc/subject";

/**
 * @deprecated Use {@link KeySize} instead.
 */
export type KeyLength = 1024 | 2048 | 3072 | 4096;

export function quote(str?: string): string {
    return `"${str || ""}"`;
}

/**
 * Subject Alternative Name (SAN) parameters for certificate
 * generation.
 */
export interface ProcessAltNamesParam {
    /** DNS host names to include in the SAN extension. */
    dns?: string[];
    /** IP addresses to include in the SAN extension. */
    ip?: string[];
    /** OPC UA application URI for the SAN extension. */
    applicationUri?: string;
}

/**
 * Options for creating a Certificate Signing Request (CSR).
 */
export interface CreateCertificateSigningRequestOptions extends ProcessAltNamesParam {
    /** X.500 subject for the certificate. */
    subject?: SubjectOptions | string;
}

/**
 * Extended CSR options that include filesystem paths and
 * certificate purpose — used internally by the OpenSSL toolbox.
 */
export interface CreateCertificateSigningRequestWithConfigOptions extends CreateCertificateSigningRequestOptions {
    /** Root directory of the PKI store. */
    rootDir: Filename;
    /** Path to the OpenSSL configuration file. */
    configFile: Filename;
    /**
     * The private key: either a filesystem path to a PEM file (unencrypted;
     * the historical behavior), or an already-resolved in-memory
     * {@link PrivateKey} — see {@link CreateSelfSignCertificateWithConfigParam.privateKey}.
     */
    privateKey: Filename | PrivateKey;
    /** Intended purpose of the certificate. */
    purpose: CertificatePurpose;
}

/**
 * Validity period parameters for certificate generation.
 */
export interface StartDateEndDateParam {
    /** Certificate "Not Before" date. Defaults to now. */
    startDate?: Date;
    /** Certificate "Not After" date (computed from validity). */
    endDate?: Date;
    /** Number of days the certificate is valid. @defaultValue 365 */
    validity?: number;
    /**
     * Certificate validity in milliseconds.
     *
     * When provided, takes precedence over {@link validity} and enables
     * sub-day validity (X.509 supports second precision per RFC 5280
     * §4.1.2.5; OpenSSL is invoked with `-startdate`/`-enddate` already).
     *
     * Typical use is short-lived certificates for demos or for renewal
     * cycle testing. Existing day-based callers are unaffected.
     */
    validityMs?: number;
}

/**
 * Parameters for creating a self-signed certificate.
 */
export interface CreateSelfSignCertificateParam extends ProcessAltNamesParam, StartDateEndDateParam {
    /** X.500 subject for the certificate. */
    subject?: SubjectOptions | string;
}

/**
 * Extended self-signed certificate options that include
 * filesystem paths and purpose — used internally.
 */
export interface CreateSelfSignCertificateWithConfigParam extends CreateSelfSignCertificateParam {
    /** Root directory of the PKI store. */
    rootDir: Filename;
    /** Path to the OpenSSL configuration file. */
    configFile: Filename;
    /**
     * The private key: either a filesystem path to a PEM file (unencrypted;
     * the historical behavior), or an already-resolved in-memory
     * {@link PrivateKey} — used when the key is passphrase-protected on
     * disk, so the decrypted key material is never written back out in
     * cleartext.
     */
    privateKey: Filename | PrivateKey;
    /** Intended purpose of the certificate. */
    purpose: CertificatePurpose;
}

/**
 * A passphrase, or a function resolving one — called lazily, and at most
 * once per `CertificateManager` / `CertificateAuthority` instance (the
 * result is cached in memory). Never logged.
 */
export type PrivateKeyPassphrase = string | (() => Promise<string>);

/**
 * Sources a {@link PrivateKey} from somewhere other than the local
 * filesystem (an HSM, a KMS, ...). When configured on `CertificateManager`,
 * it overrides disk entirely — the on-disk `own/private/private_key.pem` is
 * neither generated nor read. `CertificateAuthority` does not support a
 * provider (its signing paths are openssl reading a key file); it does
 * support `privateKeyPassphrase`.
 */
export interface PrivateKeyProvider {
    getPrivateKey(): Promise<PrivateKey>;
}

/** Resolve a {@link PrivateKeyPassphrase}, if configured. */
export async function resolvePrivateKeyPassphrase(passphrase: PrivateKeyPassphrase | undefined): Promise<string | undefined> {
    if (passphrase === undefined) {
        return undefined;
    }
    return typeof passphrase === "function" ? await passphrase() : passphrase;
}

/**
 * General-purpose parameters passed to CA operations such as
 * {@link CertificateAuthority.signCertificateRequest} and
 * {@link CertificateAuthority.revokeCertificate}.
 */
export interface Params extends ProcessAltNamesParam, StartDateEndDateParam {
    /** X.500 subject for the certificate. */
    subject?: SubjectOptions | string;

    /** Path to the private key file. */
    privateKey?: string;
    /** Path to the OpenSSL configuration file. */
    configFile?: string;
    /** Root directory of the PKI store. */
    rootDir?: string;

    /** Output filename for the generated certificate. */
    outputFile?: string;
    /** CRL revocation reason (e.g. `"keyCompromise"`). */
    reason?: string;
}

export function adjustDate(params: StartDateEndDateParam) {
    assert(params instanceof Object);
    params.startDate = params.startDate || new Date();
    assert(params.startDate instanceof Date);

    // Precedence: validityMs > validity (days) > default 365 days.
    // When validityMs is set, compute endDate via millisecond arithmetic
    // (sub-day capable). Otherwise preserve the legacy calendar-day
    // arithmetic via setDate() so day-based callers remain
    // bit-for-bit identical (including DST boundary handling).
    if (params.validityMs !== undefined) {
        if (params.validityMs <= 0) {
            throw new RangeError(`validityMs must be > 0 (got ${params.validityMs})`);
        }
        params.endDate = new Date(params.startDate.getTime() + params.validityMs);
        // Keep params.validity in sync as the ceil-rounded day count, so
        // downstream code paths that read params.validity (e.g. logging,
        // OpenSSL command echo) still see a sensible value.
        params.validity = Math.ceil(params.validityMs / 86_400_000);
    } else {
        params.validity = params.validity || 365; // one year
        params.endDate = new Date(params.startDate.getTime());
        params.endDate.setDate(params.startDate.getDate() + params.validity);
    }

    // params.endDate = x509Date(endDate);
    // params.startDate = x509Date(startDate);

    assert(params.endDate instanceof Date);
    assert(params.startDate instanceof Date);

    // // istanbul ignore next
    // if (!g_config.silent) {
    //     warningLog(" start Date ", params.startDate.toUTCString(), x509Date(params.startDate));
    //     warningLog(" end   Date ", params.endDate.toUTCString(), x509Date(params.endDate));
    // }
}

export function adjustApplicationUri(params: Params) {
    const applicationUri = params.applicationUri || "";
    if (applicationUri.length > 200) {
        throw new Error(`Openssl doesn't support urn with length greater than 200${applicationUri}`);
    }
}
