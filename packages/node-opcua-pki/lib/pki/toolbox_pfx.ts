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
import fs from "node:fs";

import type { Filename } from "../toolbox/common";
import { makePath } from "../toolbox/common2";
import { execute_openssl, passinArg, passoutArg } from "../toolbox/with_openssl/execute_openssl";

const n = makePath;

// ── Types ──────────────────────────────────────────────────────

/**
 * Options for creating a PFX (PKCS#12) file.
 */
export interface CreatePFXOptions {
    /** Path to the certificate file (PEM or DER). */
    certificateFile: Filename;

    /** Path to the private key file (PEM, plaintext or encrypted PKCS#8). */
    privateKeyFile: Filename;

    /**
     * Passphrase that decrypts `privateKeyFile` if it is an encrypted
     * PKCS#8 key (e.g. a `CertificateManager` created with
     * `privateKeyPassphrase`). Omit for a plaintext key. This is distinct
     * from `passphrase`, which protects the *output* PFX bundle.
     */
    privateKeyPassphrase?: string;

    /** Output path for the generated PFX file. */
    outputFile: Filename;

    /**
     * Optional passphrase to protect the PFX file.
     * If omitted, the PFX is created without a password.
     */
    passphrase?: string;

    /**
     * Optional path(s) to CA / intermediate certificate files
     * to include in the PFX bundle.
     */
    caCertificateFiles?: Filename[];
}

/**
 * Options for extracting data from a PFX (PKCS#12) file.
 */
export interface ExtractPFXOptions {
    /** Path to the PFX file. */
    pfxFile: Filename;

    /**
     * Passphrase used when the PFX was created.
     * Pass an empty string for unprotected PFX files.
     */
    passphrase?: string;
}

/**
 * Result of extracting data from a PFX file.
 */
export interface ExtractPFXResult {
    /** The certificate in PEM format. */
    certificate: string;

    /** The private key in PEM format. */
    privateKey: string;

    /**
     * The CA / intermediate certificates in PEM format
     * (empty string if none).
     */
    caCertificates: string;
}

// ── Create PFX ─────────────────────────────────────────────────

/**
 * Create a PFX (PKCS#12) file from a certificate and private key.
 *
 * Wraps:
 * ```
 * openssl pkcs12 -export
 *   -in <cert> -inkey <key>
 *   [-certfile <ca>]
 *   -out <pfx>
 *   -passin  env:NODE_OPCUA_PKI_OPENSSL_PASSIN
 *   -passout env:NODE_OPCUA_PKI_OPENSSL_PASSOUT
 * ```
 * Both passphrases are passed via per-invocation environment variables,
 * never placed in argv — see {@link ExecuteOptions.env}.
 * `-passin` is always present (empty when the key is plaintext) so that an
 * encrypted key without a `privateKeyPassphrase` fails fast rather than
 * leaving openssl waiting on a terminal prompt that never comes.
 *
 * @param options — see {@link CreatePFXOptions}
 */
export async function createPFX(options: CreatePFXOptions): Promise<void> {
    const { certificateFile, privateKeyFile, privateKeyPassphrase, outputFile, passphrase = "", caCertificateFiles } = options;

    assert(fs.existsSync(certificateFile), `Certificate file does not exist: ${certificateFile}`);
    assert(fs.existsSync(privateKeyFile), `Private key file does not exist: ${privateKeyFile}`);

    const args = ["pkcs12", "-export", "-in", n(certificateFile), "-inkey", n(privateKeyFile)];

    if (caCertificateFiles) {
        for (const caFile of caCertificateFiles) {
            assert(fs.existsSync(caFile), `CA certificate file does not exist: ${caFile}`);
            args.push("-certfile", n(caFile));
        }
    }

    const passin = passinArg(privateKeyPassphrase);
    const passout = passoutArg(passphrase);
    args.push("-out", n(outputFile), ...passin.args, ...passout.args);

    await execute_openssl(args, { env: { ...passin.env, ...passout.env } });
}

// ── Extract certificate from PFX ───────────────────────────────

/**
 * Extract the client/server certificate from a PFX file.
 *
 * Wraps:
 * ```
 * openssl pkcs12 -in <pfx> -clcerts -nokeys
 *   -passin env:NODE_OPCUA_PKI_OPENSSL_PASSIN
 * ```
 * The passphrase is passed via a per-invocation environment variable, never
 * placed in argv — see {@link ExecuteOptions.env}.
 *
 * @returns the certificate in PEM format.
 */
export async function extractCertificateFromPFX(options: ExtractPFXOptions): Promise<string> {
    const { pfxFile, passphrase = "" } = options;

    assert(fs.existsSync(pfxFile), `PFX file does not exist: ${pfxFile}`);

    const passin = passinArg(passphrase);
    return await execute_openssl(["pkcs12", "-in", n(pfxFile), "-clcerts", "-nokeys", "-nodes", ...passin.args], {
        env: passin.env
    });
}

// ── Extract private key from PFX ───────────────────────────────

/**
 * Extract the private key from a PFX file.
 *
 * Wraps:
 * ```
 * openssl pkcs12 -in <pfx> -nocerts -nodes
 *   -passin env:NODE_OPCUA_PKI_OPENSSL_PASSIN
 * ```
 * The passphrase is passed via a per-invocation environment variable, never
 * placed in argv — see {@link ExecuteOptions.env}.
 *
 * @returns the private key in PEM format.
 */
export async function extractPrivateKeyFromPFX(options: ExtractPFXOptions): Promise<string> {
    const { pfxFile, passphrase = "" } = options;

    assert(fs.existsSync(pfxFile), `PFX file does not exist: ${pfxFile}`);

    const passin = passinArg(passphrase);
    return await execute_openssl(["pkcs12", "-in", n(pfxFile), "-nocerts", "-nodes", ...passin.args], { env: passin.env });
}

// ── Extract CA certificates from PFX ───────────────────────────

/**
 * Extract the CA / intermediate certificates from a PFX file.
 *
 * Wraps:
 * ```
 * openssl pkcs12 -in <pfx> -cacerts -nokeys -nodes
 *   -passin env:NODE_OPCUA_PKI_OPENSSL_PASSIN
 * ```
 * The passphrase is passed via a per-invocation environment variable, never
 * placed in argv — see {@link ExecuteOptions.env}.
 *
 * @returns the CA certificates in PEM format
 *          (empty string if none are present).
 */
export async function extractCACertificatesFromPFX(options: ExtractPFXOptions): Promise<string> {
    const { pfxFile, passphrase = "" } = options;

    assert(fs.existsSync(pfxFile), `PFX file does not exist: ${pfxFile}`);

    const passin = passinArg(passphrase);
    return await execute_openssl(["pkcs12", "-in", n(pfxFile), "-cacerts", "-nokeys", "-nodes", ...passin.args], {
        env: passin.env
    });
}

// ── Extract everything from PFX ────────────────────────────────

/**
 * Extract certificate + private key + CA certs from a PFX file
 * in a single call.
 *
 * @returns an {@link ExtractPFXResult} with all PEM-encoded parts.
 */
export async function extractAllFromPFX(options: ExtractPFXOptions): Promise<ExtractPFXResult> {
    const [certificate, privateKey, caCertificates] = await Promise.all([
        extractCertificateFromPFX(options),
        extractPrivateKeyFromPFX(options),
        extractCACertificatesFromPFX(options)
    ]);
    return { certificate, privateKey, caCertificates };
}

// ── Convert PFX to PEM (combined) ──────────────────────────────

/**
 * Convert a PFX file to a single PEM file containing both the
 * certificate and the private key.
 *
 * Wraps:
 * ```
 * openssl pkcs12 -in <pfx> -out <pem> -nodes
 *   -passin env:NODE_OPCUA_PKI_OPENSSL_PASSIN
 * ```
 * The passphrase is passed via a per-invocation environment variable, never
 * placed in argv — see {@link ExecuteOptions.env}.
 */
export async function convertPFXtoPEM(pfxFile: Filename, pemFile: Filename, passphrase = ""): Promise<void> {
    assert(fs.existsSync(pfxFile), `PFX file does not exist: ${pfxFile}`);

    const passin = passinArg(passphrase);
    await execute_openssl(["pkcs12", "-in", n(pfxFile), "-out", n(pemFile), "-nodes", ...passin.args], { env: passin.env });
}

// ── Inspect PFX ────────────────────────────────────────────────

/**
 * Dump the contents of a PFX file in human-readable form.
 *
 * Wraps:
 * ```
 * openssl pkcs12 -in <pfx> -info -noout
 *   -passin env:NODE_OPCUA_PKI_OPENSSL_PASSIN
 * ```
 * The passphrase is passed via a per-invocation environment variable, never
 * placed in argv — see {@link ExecuteOptions.env}.
 *
 * @returns the human-readable dump as a string.
 */
export async function dumpPFX(pfxFile: Filename, passphrase = ""): Promise<string> {
    assert(fs.existsSync(pfxFile), `PFX file does not exist: ${pfxFile}`);

    const passin = passinArg(passphrase);
    return await execute_openssl(["pkcs12", "-in", n(pfxFile), "-info", "-nodes", ...passin.args], { env: passin.env });
}
