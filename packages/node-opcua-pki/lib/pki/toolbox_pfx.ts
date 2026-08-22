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

/**
 * PFX (PKCS#12) bundling, implemented in pure JavaScript.
 *
 * These helpers used to shell out to `openssl pkcs12`. They no longer do:
 * every function here goes through `node-opcua-crypto`, so a program that
 * only bundles and unbundles PFX files needs no `openssl` executable on the
 * machine. The exported API is unchanged.
 *
 * Two consequences are worth knowing about:
 *
 * - **What is written.** Bundles are protected with PBES2 / AES-256-CBC
 *   under an SHA-256 MAC, which is what openssl 3 produces by default and
 *   what openssl 1.x produced only when asked. Both read them back.
 * - **What can be read.** A bundle whose certificate safe uses the 40-bit
 *   RC2 encryption that openssl 1.x chose by default cannot be read here.
 *   That cipher is broken, and openssl 3 itself refuses it without
 *   `-legacy`. {@link readPfxFile} turns the failure into a message saying
 *   how to convert the file, rather than leaving an OID to be decoded by
 *   hand.
 */

import assert from "node:assert";
import fs from "node:fs";

import {
    type Certificate,
    certificateMatchesPrivateKey,
    certificatesToPem,
    coercePrivateKeyPem,
    createPfx,
    makeSHA1Thumbprint,
    type ParsedPfx,
    Pkcs12UnsupportedAlgorithmError,
    parsePfx,
    readCertificateChain,
    readPrivateKey,
    toPem,
    x509
} from "node-opcua-crypto";

import type { Filename } from "../toolbox/common";

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

    /**
     * Optional display label stored on the bundle, the equivalent of
     * openssl's `-name`. The Windows certificate store and `keytool` show
     * it; {@link extractAllFromPFX} and {@link dumpPFX} report it back.
     */
    friendlyName?: string;
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

    /** The display label the bundle carries, if it has one. */
    friendlyName?: string;
}

// ── Reading a bundle ───────────────────────────────────────────

/**
 * Open and decrypt a PFX file, reporting failures in terms of the file the
 * caller named.
 *
 * The one failure worth translating is a bundle encrypted with an algorithm
 * this implementation will not touch. In practice that means openssl 1.x's
 * default certificate-safe cipher, 40-bit RC2: the underlying error names
 * an OID, which tells the reader nothing about what to do next.
 */
async function readPfxFile(options: ExtractPFXOptions): Promise<ParsedPfx> {
    const { pfxFile, passphrase = "" } = options;

    assert(fs.existsSync(pfxFile), `PFX file does not exist: ${pfxFile}`);

    try {
        return await parsePfx(await fs.promises.readFile(pfxFile), passphrase);
    } catch (err) {
        if (err instanceof Pkcs12UnsupportedAlgorithmError) {
            const explained = new Error(
                [
                    `${pfxFile} uses an encryption algorithm that is not supported (${err.message}).`,
                    "Bundles written by openssl 1.x default to 40-bit RC2, which openssl 3 itself",
                    "rejects unless given -legacy. Convert the file once with:",
                    "  openssl pkcs12 -legacy -in old.pfx -nodes -out tmp.pem",
                    "  openssl pkcs12 -export -in tmp.pem -out new.pfx"
                ].join("\n")
            );
            // assigned rather than passed to the constructor: `lib` is empty
            // in this project, so the ES2022 ErrorOptions overload is not in
            // scope even though every supported Node runtime honours it.
            (explained as Error & { cause?: unknown }).cause = err;
            throw explained;
        }
        throw err;
    }
}

// ── Create PFX ─────────────────────────────────────────────────

/**
 * Create a PFX (PKCS#12) file from a certificate and private key.
 *
 * The bundle is protected with PBES2 / AES-256-CBC under an SHA-256 MAC. If
 * `certificateFile` holds more than one PEM block, the first is the
 * identity and the rest join the issuer chain, ahead of any
 * `caCertificateFiles`.
 *
 * Nothing is written unless every input reads back cleanly and the private
 * key belongs to the certificate, so a wrong `privateKeyPassphrase` or a
 * mismatched pair leaves no half-made file behind.
 *
 * @param options - see {@link CreatePFXOptions}
 */
export async function createPFX(options: CreatePFXOptions): Promise<void> {
    const { certificateFile, privateKeyFile, privateKeyPassphrase, outputFile, passphrase = "", caCertificateFiles } = options;

    assert(fs.existsSync(certificateFile), `Certificate file does not exist: ${certificateFile}`);
    assert(fs.existsSync(privateKeyFile), `Private key file does not exist: ${privateKeyFile}`);

    const [certificate, ...bundledIssuers] = readCertificateChain(certificateFile);
    if (!certificate) {
        throw new Error(`Certificate file holds no certificate: ${certificateFile}`);
    }

    const certificateChain: Certificate[] = [...bundledIssuers];
    for (const caFile of caCertificateFiles ?? []) {
        assert(fs.existsSync(caFile), `CA certificate file does not exist: ${caFile}`);
        certificateChain.push(...readCertificateChain(caFile));
    }

    // throws on an encrypted key with no passphrase - where the openssl
    // version would instead block on a terminal prompt that never came
    const privateKey = readPrivateKey(privateKeyFile, privateKeyPassphrase);

    // `openssl pkcs12 -export` refuses a key that does not go with the
    // certificate ("No certificate matches private key"); keep that guard,
    // or the result is a bundle nothing can use.
    if (!certificateMatchesPrivateKey(certificate, privateKey)) {
        throw new Error(`The private key ${privateKeyFile} does not match the certificate ${certificateFile}`);
    }

    const pfx = await createPfx({
        certificate,
        certificateChain,
        privateKey,
        password: passphrase,
        friendlyName: options.friendlyName
    });

    await fs.promises.writeFile(outputFile, pfx);
}

// ── Extract certificate from PFX ───────────────────────────────

/**
 * Extract the client/server certificate from a PFX file.
 *
 * @returns the certificate in PEM format.
 */
export async function extractCertificateFromPFX(options: ExtractPFXOptions): Promise<string> {
    const { certificate } = await readPfxFile(options);
    return toPem(certificate, "CERTIFICATE");
}

// ── Extract private key from PFX ───────────────────────────────

/**
 * Extract the private key from a PFX file.
 *
 * @returns the private key as unencrypted PKCS#8 PEM.
 */
export async function extractPrivateKeyFromPFX(options: ExtractPFXOptions): Promise<string> {
    const { privateKey } = await readPfxFile(options);
    return coercePrivateKeyPem(privateKey);
}

// ── Extract CA certificates from PFX ───────────────────────────

/**
 * Extract the CA / intermediate certificates from a PFX file.
 *
 * @returns the CA certificates in PEM format
 *          (empty string if none are present).
 */
export async function extractCACertificatesFromPFX(options: ExtractPFXOptions): Promise<string> {
    const { certificateChain } = await readPfxFile(options);
    return certificateChain.length === 0 ? "" : certificatesToPem(certificateChain);
}

// ── Extract everything from PFX ────────────────────────────────

/**
 * Extract certificate + private key + CA certs from a PFX file
 * in a single call.
 *
 * Prefer this over the single-part helpers when you want more than one
 * part: the file is read, decrypted and MAC-verified once here, against
 * once per part.
 *
 * @returns an {@link ExtractPFXResult} with all PEM-encoded parts.
 */
export async function extractAllFromPFX(options: ExtractPFXOptions): Promise<ExtractPFXResult> {
    const { certificate, certificateChain, privateKey, friendlyName } = await readPfxFile(options);
    return {
        certificate: toPem(certificate, "CERTIFICATE"),
        privateKey: coercePrivateKeyPem(privateKey),
        caCertificates: certificateChain.length === 0 ? "" : certificatesToPem(certificateChain),
        friendlyName
    };
}

// ── Convert PFX to PEM (combined) ──────────────────────────────

/**
 * Convert a PFX file to a single PEM file holding the private key, the
 * certificate, and any issuer certificates the bundle carries, in that
 * order.
 */
export async function convertPFXtoPEM(pfxFile: Filename, pemFile: Filename, passphrase = ""): Promise<void> {
    const { certificate, certificateChain, privateKey } = await readPfxFile({ pfxFile, passphrase });

    const parts = [coercePrivateKeyPem(privateKey), toPem(certificate, "CERTIFICATE")];
    if (certificateChain.length > 0) {
        parts.push(certificatesToPem(certificateChain));
    }
    await fs.promises.writeFile(pemFile, `${parts.map((part) => part.trimEnd()).join("\n")}\n`, "utf-8");
}

// ── Inspect PFX ────────────────────────────────────────────────

function formatThumbprint(certificate: Certificate): string {
    return (makeSHA1Thumbprint(certificate).toString("hex").toUpperCase().match(/../g) ?? []).join(":");
}

/**
 * The shape of a WebCrypto algorithm descriptor, spelled out locally: this
 * project compiles with an empty `lib`, so the DOM's `KeyAlgorithm` is not
 * in scope. RSA keys carry a `modulusLength` and EC keys a `namedCurve`;
 * neither is guaranteed, hence both optional.
 */
interface AlgorithmDescription {
    name: string;
    modulusLength?: number;
    namedCurve?: string;
}

function describePublicKey(certificate: x509.X509Certificate): string {
    const algorithm = certificate.publicKey.algorithm as AlgorithmDescription;
    if (algorithm.modulusLength) {
        return `${algorithm.name} ${algorithm.modulusLength} bits`;
    }
    if (algorithm.namedCurve) {
        return `${algorithm.name} ${algorithm.namedCurve}`;
    }
    return algorithm.name;
}

function describeCertificate(der: Certificate, indent: string): string[] {
    const certificate = new x509.X509Certificate(der);
    return [
        `${indent}subject          : ${certificate.subject}`,
        `${indent}issuer           : ${certificate.issuer}`,
        `${indent}serial number    : ${certificate.serialNumber}`,
        `${indent}not before       : ${certificate.notBefore.toISOString()}`,
        `${indent}not after        : ${certificate.notAfter.toISOString()}`,
        `${indent}public key       : ${describePublicKey(certificate)}`,
        `${indent}signature        : ${(certificate.signatureAlgorithm as unknown as AlgorithmDescription).name}`,
        `${indent}SHA-1 thumbprint : ${formatThumbprint(der)}`
    ];
}

/**
 * Dump the contents of a PFX file in human-readable form.
 *
 * The layout is this package's own, not `openssl pkcs12 -info`'s: it
 * describes the identity the bundle carries rather than the algorithms it
 * was encrypted with, and it states outright whether the enclosed key
 * matches the enclosed certificate - the question a bundle that will not
 * load is usually being asked. Treat the text as something to read, not to
 * parse; use {@link extractAllFromPFX} to get at the parts.
 *
 * @returns the human-readable dump as a string.
 */
export async function dumpPFX(pfxFile: Filename, passphrase = ""): Promise<string> {
    const { certificate, certificateChain, privateKey, friendlyName } = await readPfxFile({ pfxFile, passphrase });

    const lines = [`PFX bundle : ${pfxFile}`];
    if (friendlyName) {
        lines.push(`friendly name : ${friendlyName}`);
    }

    const keyVerdict = certificateMatchesPrivateKey(certificate, privateKey)
        ? "matches this certificate"
        : "DOES NOT match this certificate";

    lines.push("", "certificate", ...describeCertificate(certificate, "  "), `  private key      : ${keyVerdict}`);

    lines.push("", `issuer chain : ${certificateChain.length} certificate(s)`);
    for (const [index, issuer] of certificateChain.entries()) {
        lines.push(`  [${index}]`, ...describeCertificate(issuer, "    "));
    }

    return `${lines.join("\n")}\n`;
}
