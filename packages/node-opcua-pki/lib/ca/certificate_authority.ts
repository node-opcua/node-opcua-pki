// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
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
// tslint:disable:no-shadowed-variable
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import chalk from "chalk";
import {
    CertificatePurpose,
    convertPEMtoDER,
    exploreCertificate,
    exploreCertificateSigningRequest,
    generatePrivateKeyFile,
    type PrivateKey,
    readCertificatePEM,
    readCertificateSigningRequest,
    readPrivateKey,
    Subject,
    type SubjectOptions,
    toPem
} from "node-opcua-crypto";
import {
    adjustApplicationUri,
    adjustDate,
    certificateFileExist,
    debugLog,
    displaySubtitle,
    displayTitle,
    type Filename,
    type KeySize,
    makePath,
    mkdirRecursiveSync,
    type Params,
    type ProcessAltNamesParam,
    quote
} from "../toolbox";
import {
    createCertificateSigningRequestWithOpenSSL,
    type ExecuteOpenSSLOptions,
    type ExecuteOptions,
    ensure_openssl_installed,
    execute_openssl,
    execute_openssl_no_failure,
    generateStaticConfig,
    processAltNames,
    setEnv,
    x509Date
} from "../toolbox/with_openssl";

/** Default X.500 subject used when no custom subject is provided. */
export const defaultSubject = "/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=NodeOPCUA-CA";

import _simple_config_template from "../pki/templates/simple_config_template.cnf";
import _ca_config_template from "./templates/ca_config_template.cnf";

// tslint:disable-next-line:variable-name
export const configurationFileTemplate: string = _ca_config_template;
const configurationFileSimpleTemplate: string = _simple_config_template;

const config = {
    certificateDir: "INVALID",
    forceCA: false,
    pkiDir: "INVALID"
};

const n = makePath;
const q = quote;

// convert 'c07b9179'  to    "192.123.145.121"
function octetStringToIpAddress(a: string) {
    return (
        parseInt(a.substring(0, 2), 16).toString() +
        "." +
        parseInt(a.substring(2, 4), 16).toString() +
        "." +
        parseInt(a.substring(4, 6), 16).toString() +
        "." +
        parseInt(a.substring(6, 8), 16).toString()
    );
}
assert(octetStringToIpAddress("c07b9179") === "192.123.145.121");
async function construct_CertificateAuthority(certificateAuthority: CertificateAuthority): Promise<void> {
    // create the CA directory store
    // create the CA directory store
    //
    // PKI/CA
    //     |
    //     +-+> private
    //     |
    //     +-+> public
    //     |
    //     +-+> certs
    //     |
    //     +-+> crl
    //     |
    //     +-+> conf
    //     |
    //     +-f: serial
    //     +-f: crlNumber
    //     +-f: index.txt
    //

    const subject = certificateAuthority.subject;

    const caRootDir = path.resolve(certificateAuthority.rootDir);

    async function make_folders() {
        mkdirRecursiveSync(caRootDir);
        mkdirRecursiveSync(path.join(caRootDir, "private"));
        mkdirRecursiveSync(path.join(caRootDir, "public"));
        // xx execute("chmod 700 private");
        mkdirRecursiveSync(path.join(caRootDir, "certs"));
        mkdirRecursiveSync(path.join(caRootDir, "crl"));
        mkdirRecursiveSync(path.join(caRootDir, "conf"));
    }
    await make_folders();

    async function construct_default_files() {
        const serial = path.join(caRootDir, "serial");
        if (!fs.existsSync(serial)) {
            await fs.promises.writeFile(serial, "1000");
        }

        const crlNumber = path.join(caRootDir, "crlnumber");
        if (!fs.existsSync(crlNumber)) {
            await fs.promises.writeFile(crlNumber, "1000");
        }

        const indexFile = path.join(caRootDir, "index.txt");
        if (!fs.existsSync(indexFile)) {
            await fs.promises.writeFile(indexFile, "");
        }
    }

    await construct_default_files();

    const caKeyExists = fs.existsSync(path.join(caRootDir, "private/cakey.pem"));
    const caCertExists = fs.existsSync(path.join(caRootDir, "public/cacert.pem"));
    if (caKeyExists && caCertExists && !config.forceCA) {
        // CA is fully initialized => do not overwrite
        debugLog("CA private key and certificate already exist ... skipping");
        return;
    }
    if (caKeyExists && !caCertExists) {
        // Partial init: key exists but certificate does not.
        // This can happen when a previous CA creation failed
        // (e.g. OpenSSL 3.5 authorityKeyIdentifier error).
        // Remove the stale key so the CA is rebuilt from scratch.
        debugLog("CA private key exists but cacert.pem is missing — rebuilding CA");
        fs.unlinkSync(path.join(caRootDir, "private/cakey.pem"));
        // Also remove the stale CSR if present
        const staleCsr = path.join(caRootDir, "private/cakey.csr");
        if (fs.existsSync(staleCsr)) {
            fs.unlinkSync(staleCsr);
        }
    }

    // tslint:disable:no-empty
    displayTitle("Create Certificate Authority (CA)");

    const indexFileAttr = path.join(caRootDir, "index.txt.attr");
    if (!fs.existsSync(indexFileAttr)) {
        await fs.promises.writeFile(indexFileAttr, "unique_subject = no");
    }

    const caConfigFile = certificateAuthority.configFile;
    if (1 || !fs.existsSync(caConfigFile)) {
        let data = configurationFileTemplate; // inlineText(configurationFile);
        data = makePath(data.replace(/%%ROOT_FOLDER%%/, caRootDir));

        await fs.promises.writeFile(caConfigFile, data);
    }

    // http://www.akadia.com/services/ssh_test_certificate.html
    const subjectOpt = ` -subj "${subject.toString()}" `;
    processAltNames({} as Params);

    const options = { cwd: caRootDir };
    const configFile = generateStaticConfig("conf/caconfig.cnf", options);
    const configOption = ` -config ${q(n(configFile))}`;

    const keySize = certificateAuthority.keySize;

    const privateKeyFilename = path.join(caRootDir, "private/cakey.pem");
    const csrFilename = path.join(caRootDir, "private/cakey.csr");

    displayTitle(`Generate the CA private Key - ${keySize}`);
    // The first step is to create your RSA Private Key.
    // This key is a 1025,2048,3072 or 2038 bit RSA key which is encrypted using
    // Triple-DES and stored in a PEM format so that it is readable as ASCII text.
    await generatePrivateKeyFile(privateKeyFilename, keySize);
    displayTitle("Generate a certificate request for the CA key");
    // Once the private key is generated a Certificate Signing Request can be generated.
    // The CSR is then used in one of two ways. Ideally, the CSR will be sent to a Certificate Authority, such as
    // Thawte or Verisign who will verify the identity of the requestor and issue a signed certificate.
    // The second option is to self-sign the CSR, which will be demonstrated in the next section
    await execute_openssl(
        "req -new" +
            " -sha256 " +
            " -text " +
            " -extensions v3_ca_req" +
            configOption +
            " -key " +
            q(n(privateKeyFilename)) +
            " -out " +
            q(n(csrFilename)) +
            " " +
            subjectOpt,
        options
    );

    // xx // Step 3: Remove Passphrase from Key
    // xx execute("cp private/cakey.pem private/cakey.pem.org");
    // xx execute(openssl_path + " rsa -in private/cakey.pem.org -out private/cakey.pem -passin pass:"+paraphrase);

    displayTitle("Generate CA Certificate (self-signed)");
    await execute_openssl(
        " x509 -sha256 -req -days 3650 " +
            " -text " +
            " -extensions v3_ca" +
            " -extfile " +
            q(n(configFile)) +
            " -in private/cakey.csr " +
            " -signkey " +
            q(n(privateKeyFilename)) +
            " -out public/cacert.pem",
        options
    );
    displaySubtitle("generate initial CRL (Certificate Revocation List)");
    await regenerateCrl(certificateAuthority.revocationList, configOption, options);
    displayTitle("Create Certificate Authority (CA) ---> DONE");
}

async function regenerateCrl(revocationList: string, configOption: string, options: ExecuteOpenSSLOptions) {
    // produce a CRL in PEM format
    displaySubtitle("regenerate CRL (Certificate Revocation List)");
    await execute_openssl(`ca -gencrl ${configOption} -out crl/revocation_list.crl`, options);
    await execute_openssl("crl " + " -in  crl/revocation_list.crl -out  crl/revocation_list.der " + " -outform der", options);

    displaySubtitle("Display (Certificate Revocation List)");
    await execute_openssl(`crl  -in ${q(n(revocationList))} -text  -noout`, options);
}

/**
 * Options for creating a {@link CertificateAuthority}.
 */
export interface CertificateAuthorityOptions {
    /** RSA key size for the CA private key. */
    keySize: KeySize;
    /** Filesystem path where the CA directory structure is stored. */
    location: string;
    /**
     * X.500 subject for the CA certificate.
     * Accepts a slash-delimited string (e.g. `"/CN=My CA/O=Acme"`) or
     * a structured {@link SubjectOptions} object.
     *
     * @defaultValue {@link defaultSubject}
     */
    subject?: string | SubjectOptions;
}

/**
 * An OpenSSL-based Certificate Authority (CA) that can create,
 * sign, and revoke X.509 certificates.
 *
 * The CA maintains a standard OpenSSL directory layout under
 * {@link CertificateAuthority.rootDir | rootDir}:
 *
 * ```
 * <location>/
 *   ├── conf/           OpenSSL configuration
 *   ├── private/        CA private key (cakey.pem)
 *   ├── public/         CA certificate  (cacert.pem)
 *   ├── certs/          Signed certificates
 *   ├── crl/            Revocation lists
 *   ├── serial          Next serial number
 *   ├── crlnumber       Next CRL number
 *   └── index.txt       Certificate database
 * ```
 *
 * @example
 * ```ts
 * const ca = new CertificateAuthority({
 *     keySize: 2048,
 *     location: "/var/pki/CA"
 * });
 * await ca.initialize();
 * ```
 */

// ---------------------------------------------------------------
// Certificate database types (US-057)
// ---------------------------------------------------------------

/**
 * A record from the OpenSSL CA certificate database
 * (`index.txt`).
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
}

/**
 * Parse an OpenSSL date string (`YYMMDDHHmmssZ`) into an
 * ISO-8601 string.
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

/**
 * Options for {@link CertificateAuthority.signCertificateRequestFromDER}.
 *
 * All fields are optional. When provided, they override the
 * corresponding values from the CSR.
 */
export interface SignCertificateOptions {
    /** Certificate validity in days (default: 365). */
    validity?: number;
    /** Override the certificate start date. */
    startDate?: Date;
    /** Override DNS SANs. */
    dns?: string[];
    /** Override IP SANs. */
    ip?: string[];
    /** Override the application URI SAN. */
    applicationUri?: string;
    /** Override the X.500 subject. */
    subject?: SubjectOptions | string;
}

/**
 * Options for {@link CertificateAuthority.generateKeyPairAndSignDER}.
 */
export interface GenerateKeyPairAndSignOptions {
    /** OPC UA application URI (required). */
    applicationUri: string;
    /** X.500 subject for the certificate (e.g. "CN=MyApp"). */
    subject?: SubjectOptions | string;
    /** DNS host names for the SAN extension. */
    dns?: string[];
    /** IP addresses for the SAN extension. */
    ip?: string[];
    /** Certificate validity in days (default: 365). */
    validity?: number;
    /** Certificate start date (default: now). */
    startDate?: Date;
    /** RSA key size in bits (default: 2048). */
    keySize?: KeySize;
}

export class CertificateAuthority {
    /** RSA key size used when generating the CA private key. */
    public readonly keySize: KeySize;
    /** Root filesystem path of the CA directory structure. */
    public readonly location: string;
    /** X.500 subject of the CA certificate. */
    public readonly subject: Subject;

    constructor(options: CertificateAuthorityOptions) {
        assert(Object.prototype.hasOwnProperty.call(options, "location"));
        assert(Object.prototype.hasOwnProperty.call(options, "keySize"));
        this.location = options.location;
        this.keySize = options.keySize || 2048;
        this.subject = new Subject(options.subject || defaultSubject);
    }

    /** Absolute path to the CA root directory (alias for {@link location}). */
    public get rootDir() {
        return this.location;
    }

    /** Path to the OpenSSL configuration file (`conf/caconfig.cnf`). */
    public get configFile() {
        return path.normalize(path.join(this.rootDir, "./conf/caconfig.cnf"));
    }

    /** Path to the CA certificate in PEM format (`public/cacert.pem`). */
    public get caCertificate() {
        // the Certificate Authority Certificate
        return makePath(this.rootDir, "./public/cacert.pem");
    }

    /**
     * Path to the current Certificate Revocation List in DER format.
     * (`crl/revocation_list.der`)
     */
    public get revocationListDER() {
        return makePath(this.rootDir, "./crl/revocation_list.der");
    }

    /**
     * Path to the current Certificate Revocation List in PEM format.
     * (`crl/revocation_list.crl`)
     */
    public get revocationList() {
        return makePath(this.rootDir, "./crl/revocation_list.crl");
    }

    /**
     * Path to the concatenated CA certificate + CRL file.
     * Used by OpenSSL for CRL-based verification.
     */
    public get caCertificateWithCrl() {
        return makePath(this.rootDir, "./public/cacertificate_with_crl.pem");
    }

    // ---------------------------------------------------------------
    // Buffer-based accessors (US-059)
    // ---------------------------------------------------------------

    /**
     * Return the CA certificate as a DER-encoded buffer.
     *
     * @throws if the CA certificate file does not exist
     *   (call {@link initialize} first).
     */
    public getCACertificateDER(): Buffer {
        const pem = readCertificatePEM(this.caCertificate);
        return convertPEMtoDER(pem);
    }

    /**
     * Return the CA certificate as a PEM-encoded string.
     *
     * @throws if the CA certificate file does not exist
     *   (call {@link initialize} first).
     */
    public getCACertificatePEM(): string {
        const raw = readCertificatePEM(this.caCertificate);
        // OpenSSL CA cert files may include a human-readable text
        // dump before the PEM block — strip it.
        const beginMarker = "-----BEGIN CERTIFICATE-----";
        const idx = raw.indexOf(beginMarker);
        if (idx > 0) {
            return raw.substring(idx);
        }
        return raw;
    }

    /**
     * Return the current Certificate Revocation List as a
     * DER-encoded buffer.
     *
     * Returns an empty buffer if no CRL has been generated yet.
     */
    public getCRLDER(): Buffer {
        const crlPath = this.revocationListDER;
        if (!fs.existsSync(crlPath)) {
            return Buffer.alloc(0);
        }
        return fs.readFileSync(crlPath);
    }

    /**
     * Return the current Certificate Revocation List as a
     * PEM-encoded string.
     *
     * Returns an empty string if no CRL has been generated yet.
     */
    public getCRLPEM(): string {
        const crlPath = this.revocationList;
        if (!fs.existsSync(crlPath)) {
            return "";
        }
        const raw = fs.readFileSync(crlPath, "utf-8");
        // OpenSSL CRL files may include a human-readable text
        // dump before the PEM block — strip it.
        const beginMarker = "-----BEGIN X509 CRL-----";
        const idx = raw.indexOf(beginMarker);
        if (idx > 0) {
            return raw.substring(idx);
        }
        return raw;
    }

    // ---------------------------------------------------------------
    // Certificate database API (US-057)
    // ---------------------------------------------------------------

    /**
     * Return a list of all issued certificates recorded in the
     * OpenSSL `index.txt` database.
     *
     * Each entry includes the serial number, subject, status,
     * expiry date, and (for revoked certs) the revocation date.
     */
    public getIssuedCertificates(): IssuedCertificateRecord[] {
        return this._parseIndexTxt();
    }

    /**
     * Return the total number of certificates recorded in
     * `index.txt`.
     */
    public getIssuedCertificateCount(): number {
        return this._parseIndexTxt().length;
    }

    /**
     * Return the status of a certificate by its serial number.
     *
     * @param serial - hex-encoded serial number (e.g. `"1000"`)
     * @returns `"valid"`, `"revoked"`, `"expired"`, or
     *   `undefined` if not found
     */
    public getCertificateStatus(serial: string): "valid" | "revoked" | "expired" | undefined {
        const upper = serial.toUpperCase();
        const record = this._parseIndexTxt().find((r) => r.serial.toUpperCase() === upper);
        return record?.status;
    }

    /**
     * Read a specific issued certificate by serial number and
     * return its content as a DER-encoded buffer.
     *
     * OpenSSL stores signed certificates in the `certs/`
     * directory using the naming convention `<SERIAL>.pem`.
     *
     * @param serial - hex-encoded serial number (e.g. `"1000"`)
     * @returns the DER buffer, or `undefined` if not found
     */
    public getCertificateBySerial(serial: string): Buffer | undefined {
        const upper = serial.toUpperCase();
        const certFile = path.join(this.rootDir, "certs", `${upper}.pem`);
        if (!fs.existsSync(certFile)) {
            return undefined;
        }
        const pem = readCertificatePEM(certFile);
        return convertPEMtoDER(pem);
    }

    /**
     * Path to the OpenSSL certificate database file.
     */
    public get indexFile(): string {
        return path.join(this.rootDir, "index.txt");
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
    private _parseIndexTxt(): IssuedCertificateRecord[] {
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
                revocationDate: revocationDate ? parseOpenSSLDate(revocationDate) : undefined
            });
        }

        return records;
    }

    // ---------------------------------------------------------------
    // Buffer-based CA operations (US-058)
    // ---------------------------------------------------------------

    /**
     * Sign a DER-encoded Certificate Signing Request and return
     * the signed certificate as a DER buffer.
     *
     * This method handles temp-file creation and cleanup
     * internally so that callers can work with in-memory
     * buffers only.
     *
     * The CA can override fields from the CSR by passing
     * `options.dns`, `options.ip`, `options.applicationUri`,
     * `options.startDate`, or `options.subject`.
     *
     * @param csrDer - the CSR as a DER-encoded buffer
     * @param options - signing options and CA overrides
     * @returns the signed certificate as a DER-encoded buffer
     */
    public async signCertificateRequestFromDER(csrDer: Buffer, options?: SignCertificateOptions): Promise<Buffer> {
        const validity = options?.validity ?? 365;
        const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pki-sign-"));

        try {
            const csrFile = path.join(tmpDir, "request.csr");
            const certFile = path.join(tmpDir, "certificate.pem");

            // Write CSR as PEM
            const csrPem = toPem(csrDer, "CERTIFICATE REQUEST");
            await fs.promises.writeFile(csrFile, csrPem, "utf-8");

            // Build signing parameters — CA overrides take precedence
            const signingParams: Params = { validity };
            if (options?.startDate) signingParams.startDate = options.startDate;
            if (options?.dns) signingParams.dns = options.dns;
            if (options?.ip) signingParams.ip = options.ip;
            if (options?.applicationUri) signingParams.applicationUri = options.applicationUri;
            if (options?.subject) signingParams.subject = options.subject;

            // Delegate to the existing file-based method
            await this.signCertificateRequest(certFile, csrFile, signingParams);

            // Read the signed certificate and convert to DER
            const certPem = readCertificatePEM(certFile);
            return convertPEMtoDER(certPem);
        } finally {
            await fs.promises.rm(tmpDir, {
                recursive: true,
                force: true
            });
        }
    }

    /**
     * Generate a new RSA key pair, create an internal CSR, sign it
     * with this CA, and return both the certificate and private key
     * as DER-encoded buffers.
     *
     * The private key is **never stored** by the CA — it exists only
     * in a temporary directory that is cleaned up after the operation.
     *
     * This is used by `StartNewKeyPairRequest` (OPC UA Part 12) for
     * constrained devices that cannot generate their own keys.
     *
     * @param options - key generation and certificate parameters
     * @returns `{ certificateDer, privateKey }` — certificate as DER,
     *   private key as a branded `PrivateKey` buffer
     */
    public async generateKeyPairAndSignDER(options: GenerateKeyPairAndSignOptions): Promise<{
        certificateDer: Buffer;
        privateKey: PrivateKey;
    }> {
        const keySize = options.keySize ?? 2048;
        const validity = options.validity ?? 365;
        const startDate = options.startDate ?? new Date();
        const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pki-keygen-"));

        try {
            // 1. Generate ephemeral private key
            const privateKeyFile = path.join(tmpDir, "private_key.pem");
            await generatePrivateKeyFile(privateKeyFile, keySize);

            // 2. Create a minimal OpenSSL config for CSR generation
            const configFile = path.join(tmpDir, "openssl.cnf");
            await fs.promises.writeFile(configFile, configurationFileSimpleTemplate, "utf-8");

            // 3. Create CSR using the ephemeral key
            const csrFile = path.join(tmpDir, "request.csr");
            await createCertificateSigningRequestWithOpenSSL(csrFile, {
                rootDir: tmpDir,
                configFile,
                privateKey: privateKeyFile,
                applicationUri: options.applicationUri,
                subject: options.subject,
                dns: options.dns ?? [],
                ip: options.ip ?? [],
                purpose: CertificatePurpose.ForApplication
            });

            // 4. Sign the CSR with this CA
            const certFile = path.join(tmpDir, "certificate.pem");
            await this.signCertificateRequest(certFile, csrFile, {
                applicationUri: options.applicationUri,
                dns: options.dns,
                ip: options.ip,
                startDate,
                validity
            });

            // 5. Read results
            const certPem = readCertificatePEM(certFile);
            const certificateDer = convertPEMtoDER(certPem);
            const privateKey = readPrivateKey(privateKeyFile);

            return { certificateDer, privateKey };
        } finally {
            // 6. Securely clean up — private key is never persisted
            await fs.promises.rm(tmpDir, {
                recursive: true,
                force: true
            });
        }
    }

    /**
     * Revoke a DER-encoded certificate and regenerate the CRL.
     *
     * Extracts the serial number from the certificate, then
     * uses the stored cert file at `certs/<serial>.pem` for
     * revocation — avoiding temp-file PEM format mismatches.
     *
     * @param certDer - the certificate as a DER-encoded buffer
     * @param reason - CRL reason code
     *   (default: `"keyCompromise"`)
     * @throws if the certificate's serial is not found in the CA
     */
    public async revokeCertificateDER(certDer: Buffer, reason?: string): Promise<void> {
        // 1. Extract serial from the DER certificate
        const info = exploreCertificate(certDer);
        // exploreCertificate returns serial as "10:00" (colon-hex)
        // openssl stores cert files as "1000.pem" (plain hex upper)
        const serial = info.tbsCertificate.serialNumber.replace(/:/g, "").toUpperCase();

        // 2. Use the cert file that openssl ca already stored
        const storedCertFile = path.join(this.rootDir, "certs", `${serial}.pem`);
        if (!fs.existsSync(storedCertFile)) {
            throw new Error(`Cannot revoke: no stored certificate found for serial ${serial} at ${storedCertFile}`);
        }

        // 3. Delegate to the existing file-based method
        await this.revokeCertificate(storedCertFile, {
            reason: reason ?? "keyCompromise"
        });
    }

    /**
     * Initialize the CA directory structure, generate the CA
     * private key and self-signed certificate if they do not
     * already exist.
     */
    public async initialize(): Promise<void> {
        await construct_CertificateAuthority(this);
    }

    /**
     * Rebuild the combined CA certificate + CRL file.
     *
     * This concatenates the CA certificate with the current
     * revocation list so that OpenSSL can verify certificates
     * with CRL checking enabled.
     */
    public async constructCACertificateWithCRL(): Promise<void> {
        const cacertWithCRL = this.caCertificateWithCrl;

        // note : in order to check if the certificate is revoked,
        // you need to specify -crl_check and have both the CA cert and the (applicable) CRL in your trust store.
        // There are two ways to do that:
        // 1. concatenate cacert.pem and crl.pem into one file and use that for -CAfile.
        // 2. use some linked
        // ( from http://security.stackexchange.com/a/58305/59982)

        if (fs.existsSync(this.revocationList)) {
            await fs.promises.writeFile(
                cacertWithCRL,
                fs.readFileSync(this.caCertificate, "utf8") + fs.readFileSync(this.revocationList, "utf8")
            );
        } else {
            // there is no revocation list yet
            await fs.promises.writeFile(cacertWithCRL, fs.readFileSync(this.caCertificate));
        }
    }

    /**
     * Append the CA certificate to a signed certificate file,
     * creating a PEM certificate chain.
     *
     * @param certificate - path to the certificate file to extend
     */
    public async constructCertificateChain(certificate: Filename): Promise<void> {
        assert(fs.existsSync(certificate));
        assert(fs.existsSync(this.caCertificate));

        debugLog(chalk.yellow("        certificate file :"), chalk.cyan(certificate));
        // append
        await fs.promises.writeFile(
            certificate,
            (await fs.promises.readFile(certificate, "utf8")) + (await fs.promises.readFile(this.caCertificate, "utf8"))
            //   + fs.readFileSync(this.revocationList)
        );
    }

    /**
     * Create a self-signed certificate using OpenSSL.
     *
     * @param certificateFile - output path for the signed certificate
     * @param privateKey - path to the private key file
     * @param params - certificate parameters (subject, validity, SANs)
     */
    public async createSelfSignedCertificate(certificateFile: Filename, privateKey: Filename, params: Params): Promise<void> {
        assert(typeof privateKey === "string");
        assert(fs.existsSync(privateKey));

        if (!certificateFileExist(certificateFile)) {
            return;
        }

        adjustDate(params);
        adjustApplicationUri(params);
        processAltNames(params);

        const csrFile = `${certificateFile}_csr`;
        assert(csrFile);
        const configFile = generateStaticConfig(this.configFile, { cwd: this.rootDir });

        const options = {
            cwd: this.rootDir,
            openssl_conf: makePath(configFile)
        };

        const configOption = "";

        const subject = params.subject ? new Subject(params.subject).toString() : "";
        const subjectOptions = subject && subject.length > 1 ? ` -subj ${subject} ` : "";

        displaySubtitle("- the certificate signing request");
        await execute_openssl(
            "req " +
                " -new -sha256 -text " +
                configOption +
                subjectOptions +
                " -batch -key " +
                q(n(privateKey)) +
                " -out " +
                q(n(csrFile)),
            options
        );

        displaySubtitle("- creating the self-signed certificate");
        await execute_openssl(
            "ca " +
                " -selfsign " +
                " -keyfile " +
                q(n(privateKey)) +
                " -startdate " +
                x509Date(params.startDate) +
                " -enddate " +
                x509Date(params.endDate) +
                " -batch -out " +
                q(n(certificateFile)) +
                " -in " +
                q(n(csrFile)),
            options
        );

        displaySubtitle("- dump the certificate for a check");

        await execute_openssl(`x509 -in ${q(n(certificateFile))}  -dates -fingerprint -purpose -noout`, {});

        displaySubtitle("- verify self-signed certificate");
        await execute_openssl_no_failure(`verify -verbose -CAfile ${q(n(certificateFile))} ${q(n(certificateFile))}`, options);

        await fs.promises.unlink(csrFile);
    }

    /**
     * Revoke a certificate and regenerate the CRL.
     *
     * @param certificate - path to the certificate file to revoke
     * @param params - revocation parameters
     * @param params.reason - CRL reason code
     *   (default `"keyCompromise"`)
     */
    public async revokeCertificate(certificate: Filename, params: Params): Promise<void> {
        const crlReasons = [
            "unspecified",
            "keyCompromise",
            "CACompromise",
            "affiliationChanged",
            "superseded",
            "cessationOfOperation",
            "certificateHold",
            "removeFromCRL"
        ];

        const configFile = generateStaticConfig("conf/caconfig.cnf", { cwd: this.rootDir });

        const options = {
            cwd: this.rootDir,
            openssl_conf: makePath(configFile)
        };

        setEnv("ALTNAME", "");
        const randomFile = path.join(this.rootDir, "random.rnd");
        setEnv("RANDFILE", randomFile);

        // // tslint:disable-next-line:no-string-literal
        // if (!fs.existsSync((process.env as any)["OPENSSL_CONF"])) {
        //     throw new Error("Cannot find OPENSSL_CONF");
        // }

        const configOption = ` -config ${q(n(configFile))}`;

        const reason = params.reason || "keyCompromise";
        assert(crlReasons.indexOf(reason) >= 0);

        displayTitle(`Revoking certificate  ${certificate}`);

        displaySubtitle("Revoke certificate");

        await execute_openssl_no_failure(`ca -verbose ${configOption} -revoke ${q(certificate)} -crl_reason ${reason}`, options);
        // regenerate CRL (Certificate Revocation List)
        await regenerateCrl(this.revocationList, configOption, options);

        displaySubtitle("Verify that certificate is revoked");

        await execute_openssl_no_failure(
            "verify -verbose" +
                // configOption +
                " -CRLfile " +
                q(n(this.revocationList)) +
                " -CAfile " +
                q(n(this.caCertificate)) +
                " -crl_check " +
                q(n(certificate)),
            options
        );

        // produce CRL in DER format
        displaySubtitle("Produce CRL in DER form ");
        await execute_openssl(`crl  -in ${q(n(this.revocationList))} -out crl/revocation_list.der  -outform der`, options);
        // produce CRL in PEM format with text
        displaySubtitle("Produce CRL in PEM form ");

        await execute_openssl(`crl  -in ${q(n(this.revocationList))} -out crl/revocation_list.pem  -outform pem -text `, options);
    }

    /**
     * Sign a Certificate Signing Request (CSR) with this CA.
     *
     * The signed certificate is written to `certificate`, and the
     * CA certificate chain plus CRL are appended to form a
     * complete certificate chain.
     *
     * @param certificate - output path for the signed certificate
     * @param certificateSigningRequestFilename - path to the CSR
     * @param params1 - signing parameters (validity, dates, SANs)
     * @returns the path to the signed certificate
     */
    public async signCertificateRequest(
        certificate: Filename,
        certificateSigningRequestFilename: Filename,
        params1: Params
    ): Promise<Filename> {
        await ensure_openssl_installed();
        assert(fs.existsSync(certificateSigningRequestFilename));
        if (!certificateFileExist(certificate)) {
            return "";
        }
        adjustDate(params1);
        adjustApplicationUri(params1);
        processAltNames(params1);

        const options: ExecuteOptions = { cwd: this.rootDir };

        // note :
        // subjectAltName is not copied across
        //  see https://github.com/openssl/openssl/issues/10458
        const csr = await readCertificateSigningRequest(certificateSigningRequestFilename);
        const csrInfo = exploreCertificateSigningRequest(csr);

        const applicationUri = csrInfo.extensionRequest.subjectAltName.uniformResourceIdentifier
            ? csrInfo.extensionRequest.subjectAltName.uniformResourceIdentifier[0]
            : undefined;
        if (typeof applicationUri !== "string") {
            throw new Error("Cannot find applicationUri in CSR");
        }

        const dns = csrInfo.extensionRequest.subjectAltName.dNSName || [];
        let ip = csrInfo.extensionRequest.subjectAltName.iPAddress || [];
        ip = ip.map(octetStringToIpAddress);

        const params: ProcessAltNamesParam = {
            applicationUri,
            dns,
            ip
        };

        processAltNames(params);

        const configFile = generateStaticConfig("conf/caconfig.cnf", options);

        displaySubtitle("- then we ask the authority to sign the certificate signing request");

        const configOption = ` -config ${configFile}`;
        await execute_openssl(
            "ca " +
                configOption +
                " -startdate " +
                x509Date(params1.startDate) +
                " -enddate " +
                x509Date(params1.endDate) +
                " -batch -out " +
                q(n(certificate)) +
                " -in " +
                q(n(certificateSigningRequestFilename)),
            options
        );

        displaySubtitle("- dump the certificate for a check");
        await execute_openssl(`x509 -in ${q(n(certificate))}  -dates -fingerprint -purpose -noout`, options);

        displaySubtitle("- construct CA certificate with CRL");
        await this.constructCACertificateWithCRL();

        // construct certificate chain
        //   concatenate certificate with CA Certificate and revocation list
        displaySubtitle("- construct certificate chain");
        await this.constructCertificateChain(certificate);
        // todo
        displaySubtitle("- verify certificate against the root CA");
        await this.verifyCertificate(certificate);

        return certificate;
    }

    /**
     * Verify a certificate against this CA.
     *
     * @param certificate - path to the certificate file to verify
     */
    public async verifyCertificate(certificate: Filename): Promise<void> {
        // openssl verify crashes on windows! we cannot use it reliably
        // istanbul ignore next
        const isImplemented = false;

        // istanbul ignore next
        if (isImplemented) {
            const options = { cwd: this.rootDir };
            const configFile = generateStaticConfig("conf/caconfig.cnf", options);

            setEnv("OPENSSL_CONF", makePath(configFile));
            const _configOption = ` -config ${configFile}`;
            _configOption;
            await execute_openssl_no_failure(
                `verify -verbose  -CAfile ${q(n(this.caCertificateWithCrl))} ${q(n(certificate))}`,
                options
            );
        }
    }
}
