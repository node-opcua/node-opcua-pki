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
import { convertPEMtoDER, readCertificatePEM } from "node-opcua-crypto";

/**
 * A record from the OpenSSL CA certificate database (`index.txt`).
 */
export interface IssuedCertificateRecord {
    /** Hex-encoded serial number (e.g. `"1000"`). */
    serial: string;
    /** Certificate status. */
    status: "valid" | "revoked" | "expired";
    /** X.500 subject string (slash-delimited). */
    subject: string;
    /** Certificate expiry date as ISO-8601 string. */
    expiryDate: string;
    /**
     * Revocation date as ISO-8601 string.
     * Only present when `status === "revoked"`.
     */
    revocationDate?: string;
    /**
     * CRL revocation reason (e.g. `"keyCompromise"`), as stored after the
     * comma in the revocation-date field. Only present when
     * `status === "revoked"` and a reason was recorded.
     */
    reason?: string;
}

/**
 * Parse an OpenSSL date string (`YYMMDDHHmmssZ`) into an ISO-8601 string.
 */
function parseOpenSSLDate(dateStr: string): string {
    // Revocation dates may have a reason suffix: "YYMMDDHHmmssZ,reason"
    // Strip anything after the first comma.
    const raw = dateStr?.split(",")[0] ?? "";
    if (raw.length < 12) return "";
    // OpenSSL uses 2-digit year; 70+ is 19xx, <70 is 20xx
    const yy = parseInt(raw.substring(0, 2), 10);
    const year = yy >= 70 ? 1900 + yy : 2000 + yy;
    const month = raw.substring(2, 4);
    const day = raw.substring(4, 6);
    const hour = raw.substring(6, 8);
    const min = raw.substring(8, 10);
    const sec = raw.substring(10, 12);
    return `${year}-${month}-${day}T${hour}:${min}:${sec}Z`;
}

/** The inverse of {@link parseOpenSSLDate}: format a `Date` as `YYMMDDHHmmssZ` (UTC). */
function formatOpenSSLDate(date: Date): string {
    const yy = String(date.getUTCFullYear() % 100).padStart(2, "0");
    const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(date.getUTCDate()).padStart(2, "0");
    const hh = String(date.getUTCHours()).padStart(2, "0");
    const mi = String(date.getUTCMinutes()).padStart(2, "0");
    const ss = String(date.getUTCSeconds()).padStart(2, "0");
    return `${yy}${mm}${dd}${hh}${mi}${ss}Z`;
}

/** Extract the reason suffix (after the first comma) from a revocation-date field, if any. */
function parseRevocationReason(dateStr: string): string | undefined {
    const parts = dateStr?.split(",");
    return parts && parts.length > 1 ? parts[1] : undefined;
}

/** Pad a hex string to an even number of digits, matching OpenSSL's `serial`/`crlnumber` file convention. */
function evenLengthHex(value: bigint): string {
    const hex = value.toString(16).toUpperCase();
    return hex.length % 2 === 0 ? hex : `0${hex}`;
}

/**
 * Escape every control character (and backslash) as `\xHH`, the way
 * OpenSSL's `X509_NAME_oneline` does before writing a subject to
 * `index.txt`. `index.txt` is a tab/newline-delimited table: a subject
 * (which comes verbatim from the requester's CSR, so is attacker
 * controlled) containing a raw `\n` or `\t` would otherwise inject a
 * forged row — e.g. an `R` entry naming a victim's serial, which the next
 * CRL regeneration would then faithfully publish as revoked.
 */
function escapeIndexField(value: string): string {
    // biome-ignore lint/suspicious/noControlCharactersInRegex: escaping control characters is the point
    return value.replace(/[\x00-\x1f\x7f\\]/g, (c) => `\\x${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`);
}

/** A hex serial handed to a writer must be exactly that — never something that could carry a field or row separator. */
function assertHexSerial(serial: string): string {
    if (!/^[0-9A-Fa-f]+$/.test(serial)) {
        throw new Error(`Invalid certificate serial number: ${JSON.stringify(serial)}`);
    }
    return serial.toUpperCase();
}

/**
 * Read and write access to a CA's OpenSSL-format certificate database
 * (`index.txt`, `serial`, `crlnumber`, `certs/<SERIAL>.pem`).
 *
 * This is the format `openssl ca` itself writes and reads; every mutating
 * method here (`nextSerial`, `nextCrlNumber`, `appendIssued`, `markRevoked`,
 * `storeCertificate`) exists so a native (non-openssl) signing backend can
 * write the exact same on-disk format `openssl ca` does, so an install can
 * move between backends and external `openssl` tooling keeps working on the
 * same directory. Callers are responsible for serializing access — every
 * mutating call must happen under the owning CA's directory lock
 * (`CertificateAuthority._withCaDirectoryLock`), the same guarantee
 * `OpenSslCaBackend` gets from the lock around each `openssl ca` /
 * `openssl x509 -CAserial` invocation.
 */
export class CaDatabase {
    readonly #rootDir: string;

    constructor(rootDir: string) {
        this.#rootDir = rootDir;
    }

    /** Path to the OpenSSL certificate database file (`index.txt`). */
    public get indexFile(): string {
        return path.join(this.#rootDir, "index.txt");
    }

    /**
     * Parse the OpenSSL `index.txt` certificate database.
     *
     * Each line has tab-separated fields:
     * ```
     * status  expiry  [revocationDate]  serial  unknown  subject
     * ```
     *
     * - status: `V` (valid), `R` (revoked), `E` (expired)
     * - expiry: `YYMMDDHHmmssZ`
     * - revocationDate: present only for revoked certs
     * - serial: hex string
     * - unknown: always `"unknown"`
     * - subject: X.500 slash-delimited string
     */
    public readIndex(): IssuedCertificateRecord[] {
        const indexPath = this.indexFile;
        if (!fs.existsSync(indexPath)) {
            return [];
        }

        const content = fs.readFileSync(indexPath, "utf-8");
        const lines = content.split("\n").filter((l) => l.trim().length > 0);
        const records: IssuedCertificateRecord[] = [];

        for (const line of lines) {
            const fields = line.split("\t");
            if (fields.length < 4) continue;

            const statusChar = fields[0];
            const expiryStr = fields[1];

            let serial: string;
            let subject: string;
            let revocationDate: string | undefined;

            if (statusChar === "R") {
                // Revoked: status  expiry  revocationDate  serial  unknown  subject
                revocationDate = fields[2];
                serial = fields[3];
                subject = fields.length >= 6 ? fields[5] : "";
            } else {
                // Valid/Expired: status  expiry  (empty)  serial  unknown  subject
                serial = fields[3];
                subject = fields.length >= 6 ? fields[5] : "";
            }

            let status: "valid" | "revoked" | "expired";
            switch (statusChar) {
                case "V":
                    status = "valid";
                    break;
                case "R":
                    status = "revoked";
                    break;
                case "E":
                    status = "expired";
                    break;
                default:
                    continue; // skip unknown status
            }

            records.push({
                serial,
                status,
                subject,
                expiryDate: parseOpenSSLDate(expiryStr),
                revocationDate: revocationDate ? parseOpenSSLDate(revocationDate) : undefined,
                reason: revocationDate ? parseRevocationReason(revocationDate) : undefined
            });
        }

        return records;
    }

    /** Look up one record by serial number (case-insensitive). */
    public findBySerial(serial: string): IssuedCertificateRecord | undefined {
        const upper = serial.toUpperCase();
        return this.readIndex().find((r) => r.serial.toUpperCase() === upper);
    }

    /**
     * Read a specific issued certificate by serial number.
     *
     * OpenSSL stores signed certificates in the `certs/` directory using
     * the naming convention `<SERIAL>.pem`.
     *
     * @param serial - hex-encoded serial number (e.g. `"1000"`)
     * @returns the DER buffer, or `undefined` if not found
     */
    public getCertificateBySerial(serial: string): Buffer | undefined {
        const upper = serial.toUpperCase();
        const certFile = path.join(this.#rootDir, "certs", `${upper}.pem`);
        if (!fs.existsSync(certFile)) {
            return undefined;
        }
        const pem = readCertificatePEM(certFile);
        return convertPEMtoDER(pem);
    }

    /**
     * Read-increment-write a hex counter file (`serial`/`crlnumber`),
     * returning the value to hand out — matching `openssl ca`'s own
     * behavior: the file holds the *next* value to assign, and is bumped
     * to the following one immediately after being read. A `.old` backup
     * of the pre-bump content is kept, as `openssl` itself does.
     */
    #nextHexCounter(fileName: string): string {
        const counterFile = path.join(this.#rootDir, fileName);
        const current = BigInt(`0x${fs.readFileSync(counterFile, "utf-8").trim()}`);
        fs.copyFileSync(counterFile, `${counterFile}.old`);
        fs.writeFileSync(counterFile, evenLengthHex(current + 1n));
        return evenLengthHex(current);
    }

    /** Hand out the next certificate serial number, bumping the `serial` file. */
    public nextSerial(): string {
        return this.#nextHexCounter("serial");
    }

    /** Hand out the next CRL number, bumping the `crlnumber` file. */
    public nextCrlNumber(): string {
        return this.#nextHexCounter("crlnumber");
    }

    /** Append a newly-issued certificate's `V` (valid) row to `index.txt`. */
    public appendIssued(record: { serial: string; expiryDate: Date; subject: string }): void {
        const serial = assertHexSerial(record.serial);
        const subject = escapeIndexField(record.subject);
        const line = `V\t${formatOpenSSLDate(record.expiryDate)}\t\t${serial}\tunknown\t${subject}\n`;
        fs.appendFileSync(this.indexFile, line);
    }

    /**
     * Rewrite a certificate's `index.txt` row from `V` to `R` (revoked).
     * Throws if the serial is not found, or is already revoked — the same
     * "already revoked" case `openssl ca -revoke` itself rejects.
     */
    public markRevoked(serial: string, revocationDate: Date, reason: string): void {
        const upper = assertHexSerial(serial);
        if (!/^[A-Za-z]+$/.test(reason)) {
            throw new Error(`Invalid CRL reason: ${JSON.stringify(reason)}`);
        }
        const lines = fs
            .readFileSync(this.indexFile, "utf-8")
            .split("\n")
            .filter((l) => l.trim().length > 0);

        let found = false;
        const rewritten = lines.map((line) => {
            const fields = line.split("\t");
            if (fields.length < 4 || fields[3]?.toUpperCase() !== upper) {
                return line;
            }
            if (fields[0] === "R") {
                throw new Error(`Certificate ${upper} is already revoked`);
            }
            found = true;
            const subject = fields.length >= 6 ? fields[5] : "";
            return `R\t${fields[1]}\t${formatOpenSSLDate(revocationDate)},${reason}\t${upper}\tunknown\t${subject}`;
        });

        if (!found) {
            throw new Error(`Certificate ${upper} not found in the certificate database`);
        }
        fs.writeFileSync(this.indexFile, `${rewritten.join("\n")}\n`);
    }

    /** Store a signed certificate's PEM under `certs/<SERIAL>.pem`, as `openssl ca` does. */
    public storeCertificate(serial: string, pem: string): void {
        const certFile = path.join(this.#rootDir, "certs", `${assertHexSerial(serial)}.pem`);
        fs.writeFileSync(certFile, pem);
    }
}
