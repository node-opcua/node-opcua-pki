// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2025 - Sterfive.com
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
import assert from "assert";
import chalk from "chalk";
import fs from "fs";
import path from "path";

import {
    Subject,
    SubjectOptions,
    exploreCertificateSigningRequest,
    readCertificateSigningRequest,
    generatePrivateKeyFile,
} from "node-opcua-crypto";

import {
    Filename,
    KeySize,
    certificateFileExist,
    make_path,
    mkdir,
    debugLog,
    adjustApplicationUri,
    adjustDate,
    displaySubtitle,
    displayTitle,
    Params,
    ProcessAltNamesParam,
    quote,
} from "../toolbox";

import {
    setEnv,
    generateStaticConfig,
    processAltNames,
    ensure_openssl_installed,
    x509Date,
    execute_openssl_no_failure,
    ExecuteOptions,
    execute_openssl,
    ExecuteOpenSSLOptions,
} from "../toolbox/with_openssl";

export const defaultSubject = "/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=NodeOPCUA-CA";

import _ca_config_template from "./templates/ca_config_template.cnf";

// tslint:disable-next-line:variable-name
export const configurationFileTemplate: string = _ca_config_template;

const config = {
    certificateDir: "INVALID",
    forceCA: false,
    pkiDir: "INVALID",
};

const n = make_path;
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

    const caRootDir = certificateAuthority.rootDir;

    async function make_folders() {
        await mkdir(caRootDir);
        await mkdir(path.join(caRootDir, "private"));
        await mkdir(path.join(caRootDir, "public"));
        // xx execute("chmod 700 private");
        await mkdir(path.join(caRootDir, "certs"));
        await mkdir(path.join(caRootDir, "crl"));
        await mkdir(path.join(caRootDir, "conf"));
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

    if (fs.existsSync(path.join(caRootDir, "private/cakey.pem")) && !config.forceCA) {
        // certificate already exists => do not overwrite
        debugLog("CA private key already exists ... skipping");
        return;
    }

    // tslint:disable:no-empty
    displayTitle("Create Certificate Authority (CA)");

    const indexFileAttr = path.join(caRootDir, "index.txt.attr");
    if (!fs.existsSync(indexFileAttr)) {
        await fs.promises.writeFile(indexFileAttr, "unique_subject = no");
    }

    const caConfigFile = certificateAuthority.configFile;
    // eslint-disable-next-line no-constant-condition
    if (1 || !fs.existsSync(caConfigFile)) {
        let data = configurationFileTemplate; // inlineText(configurationFile);
        data = data.replace(/%%ROOT_FOLDER%%/, make_path(caRootDir));

        await fs.promises.writeFile(caConfigFile, data);
    }

    // http://www.akadia.com/services/ssh_test_certificate.html
    const subjectOpt = ' -subj "' + subject.toString() + '" ';
    const options = { cwd: caRootDir };
    processAltNames({} as Params);

    const configFile = generateStaticConfig("conf/caconfig.cnf", options);
    const configOption = " -config " + q(n(configFile));

    const keySize = certificateAuthority.keySize;

    const privateKeyFilename = path.join(caRootDir, "private/cakey.pem");
    const csrFilename = path.join(caRootDir, "private/cakey.csr");

    displayTitle("Generate the CA private Key - " + keySize),
        // The first step is to create your RSA Private Key.
        // This key is a 1025,2048,3072 or 2038 bit RSA key which is encrypted using
        // Triple-DES and stored in a PEM format so that it is readable as ASCII text.
        await generatePrivateKeyFile(privateKeyFilename, keySize),
        displayTitle("Generate a certificate request for the CA key"),
        // Once the private key is generated a Certificate Signing Request can be generated.
        // The CSR is then used in one of two ways. Ideally, the CSR will be sent to a Certificate Authority, such as
        // Thawte or Verisign who will verify the identity of the requestor and issue a signed certificate.
        // The second option is to self-sign the CSR, which will be demonstrated in the next section
        await execute_openssl(
            "req -new" +
                " -sha256 " +
                " -text " +
                " -extensions v3_ca" +
                configOption +
                " -key " +
                q(n(privateKeyFilename)) +
                " -out " +
                q(n(csrFilename)) +
                " " +
                subjectOpt,
            options,
        );

    // xx // Step 3: Remove Passphrase from Key
    // xx execute("cp private/cakey.pem private/cakey.pem.org");
    // xx execute(openssl_path + " rsa -in private/cakey.pem.org -out private/cakey.pem -passin pass:"+paraphrase);

    displayTitle("Generate CA Certificate (self-signed)"),
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
            options,
        ),
        displaySubtitle("generate initial CRL (Certificate Revocation List)"),
        await regenerateCrl(certificateAuthority.revocationList, configOption, options),
        displayTitle("Create Certificate Authority (CA) ---> DONE");
}

async function regenerateCrl(revocationList: string, configOption: string, options: ExecuteOpenSSLOptions) {
    // produce a CRL in PEM format
    displaySubtitle("regenerate CRL (Certificate Revocation List)");
    await execute_openssl("ca -gencrl " + configOption + " -out crl/revocation_list.crl", options);
    await execute_openssl("crl " + " -in  crl/revocation_list.crl -out  crl/revocation_list.der " + " -outform der", options);

    displaySubtitle("Display (Certificate Revocation List)");
    await execute_openssl("crl " + " -in " + q(n(revocationList)) + " -text " + " -noout", options);
}

export interface CertificateAuthorityOptions {
    keySize: KeySize;
    location: string;
    subject?: string | SubjectOptions;
}

export class CertificateAuthority {
    public readonly keySize: KeySize;
    public readonly location: string;
    public readonly subject: Subject;

    constructor(options: CertificateAuthorityOptions) {
        assert(Object.prototype.hasOwnProperty.call(options, "location"));
        assert(Object.prototype.hasOwnProperty.call(options, "keySize"));
        this.location = options.location;
        this.keySize = options.keySize || 2048;
        this.subject = new Subject(options.subject || defaultSubject);
    }

    public get rootDir() {
        return this.location;
    }

    public get configFile() {
        return path.normalize(path.join(this.rootDir, "./conf/caconfig.cnf"));
    }

    public get caCertificate() {
        // the Certificate Authority Certificate
        return make_path(this.rootDir, "./public/cacert.pem");
    }

    /**
     * the file name where  the current Certificate Revocation List is stored (in DER format)
     */
    public get revocationListDER() {
        return make_path(this.rootDir, "./crl/revocation_list.der");
    }

    /**
     * the file name where  the current Certificate Revocation List is stored (in PEM format)
     */
    public get revocationList() {
        return make_path(this.rootDir, "./crl/revocation_list.crl");
    }

    public get caCertificateWithCrl() {
        return make_path(this.rootDir, "./public/cacertificate_with_crl.pem");
    }

    public async initialize(): Promise<void> {
        await construct_CertificateAuthority(this);
    }

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
                fs.readFileSync(this.caCertificate, "utf8") + fs.readFileSync(this.revocationList, "utf8"),
            );
        } else {
            // there is no revocation list yet
            await fs.promises.writeFile(cacertWithCRL, fs.readFileSync(this.caCertificate));
        }
    }

    public async constructCertificateChain(certificate: Filename): Promise<void> {
        assert(fs.existsSync(certificate));
        assert(fs.existsSync(this.caCertificate));

        debugLog(chalk.yellow("        certificate file :"), chalk.cyan(certificate));
        // append
        await fs.promises.writeFile(
            certificate,
            (await fs.promises.readFile(certificate, "utf8")) + (await fs.promises.readFile(this.caCertificate, "utf8")),
            //   + fs.readFileSync(this.revocationList)
        );
    }

    public async createSelfSignedCertificate(certificateFile: Filename, privateKey: Filename, params: Params): Promise<void> {
        assert(typeof privateKey === "string");
        assert(fs.existsSync(privateKey));

        if (!certificateFileExist(certificateFile)) {
            return;
        }

        adjustDate(params);
        adjustApplicationUri(params);
        processAltNames(params);

        const csrFile = certificateFile + "_csr";
        assert(csrFile);
        const configFile = generateStaticConfig(this.configFile);

        const options = {
            cwd: this.rootDir,
            openssl_conf: make_path(configFile),
        };

        const configOption = "";

        const subject = params.subject ? new Subject(params.subject!).toString() : "";
        const subjectOptions = subject && subject.length > 1 ? " -subj " + subject + " " : "";

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
            options,
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
            options,
        );

        displaySubtitle("- dump the certificate for a check");

        await execute_openssl("x509 -in " + q(n(certificateFile)) + "  -dates -fingerprint -purpose -noout", {});

        displaySubtitle("- verify self-signed certificate");
        await execute_openssl_no_failure("verify -verbose -CAfile " + q(n(certificateFile)) + " " + q(n(certificateFile)), options);

        await fs.promises.unlink(csrFile);
    }

    /**
     * revoke a certificate and update the CRL
     *
     * @method revokeCertificate
     * @param certificate -  the certificate to revoke
     * @param params
     * @param [params.reason = "keyCompromise" {String}]
     * @async
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
            "removeFromCRL",
        ];

        const configFile = generateStaticConfig("conf/caconfig.cnf", { cwd: this.rootDir });

        const options = {
            cwd: this.rootDir,
            openssl_conf: make_path(configFile),
        };

        setEnv("ALTNAME", "");
        const randomFile = path.join(this.rootDir, "random.rnd");
        setEnv("RANDFILE", randomFile);

        // // tslint:disable-next-line:no-string-literal
        // if (!fs.existsSync((process.env as any)["OPENSSL_CONF"])) {
        //     throw new Error("Cannot find OPENSSL_CONF");
        // }

        const configOption = " -config " + q(n(configFile));

        const reason = params.reason || "keyCompromise";
        assert(crlReasons.indexOf(reason) >= 0);

        await displayTitle("Revoking certificate  " + certificate);

        await displaySubtitle("Revoke certificate");

        await execute_openssl_no_failure(
            "ca -verbose " + configOption + " -revoke " + q(certificate) + " -crl_reason " + reason,
            options,
        );
        // regenerate CRL (Certificate Revocation List)
        await regenerateCrl(this.revocationList, configOption, options);

        await displaySubtitle("Verify that certificate is revoked");

        await execute_openssl_no_failure(
            "verify -verbose" +
                // configOption +
                " -CRLfile " +
                q(n(this.revocationList)) +
                " -CAfile " +
                q(n(this.caCertificate)) +
                " -crl_check " +
                q(n(certificate)),
            options,
        );

        // produce CRL in DER format
        await displaySubtitle("Produce CRL in DER form ");
        await execute_openssl(
            "crl " + " -in " + q(n(this.revocationList)) + " -out " + "crl/revocation_list.der " + " -outform der",
            options,
        );
        // produce CRL in PEM format with text
        await displaySubtitle("Produce CRL in PEM form "),
            await execute_openssl(
                "crl " + " -in " + q(n(this.revocationList)) + " -out " + "crl/revocation_list.pem " + " -outform pem" + " -text ",
                options,
            );
    }

    /**
     *
     * @param certificate            - the certificate filename to generate
     * @param certificateSigningRequestFilename   - the certificate signing request
     * @param params                 - parameters
     * @param params.applicationUri  - the applicationUri
     * @param params.startDate       - startDate of the certificate
     * @param params.validity        - number of day of validity of the certificate
     */
    public async signCertificateRequest(
        certificate: Filename,
        certificateSigningRequestFilename: Filename,
        params1: Params,
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
        let configFile: string;

        // note :
        // subjectAltName is not copied across
        //  see https://github.com/openssl/openssl/issues/10458
        const csr = await readCertificateSigningRequest(certificateSigningRequestFilename);
        const csrInfo = exploreCertificateSigningRequest(csr);

        const applicationUri = csrInfo.extensionRequest.subjectAltName.uniformResourceIdentifier[0];
        if (typeof applicationUri !== "string") {
            throw new Error("Cannot find applicationUri in CSR");
        }

        const dns = csrInfo.extensionRequest.subjectAltName.dNSName || [];
        let ip = csrInfo.extensionRequest.subjectAltName.iPAddress || [];
        ip = ip.map(octetStringToIpAddress);

        const params: ProcessAltNamesParam = {
            applicationUri,
            dns,
            ip,
        };

        processAltNames(params);

        configFile = generateStaticConfig("conf/caconfig.cnf", options);

        displaySubtitle("- then we ask the authority to sign the certificate signing request");

        const configOption = " -config " + configFile;
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
            options,
        );

        displaySubtitle("- dump the certificate for a check");
        await execute_openssl("x509 -in " + q(n(certificate)) + "  -dates -fingerprint -purpose -noout", options);

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

    public async verifyCertificate(certificate: Filename): Promise<void> {
        // openssl verify crashes on windows! we cannot use it reliably
        // istanbul ignore next
        const isImplemented = false;

        // istanbul ignore next
        if (isImplemented) {
            const options = { cwd: this.rootDir };
            const configFile = generateStaticConfig("conf/caconfig.cnf", options);

            setEnv("OPENSSL_CONF", make_path(configFile));
            const configOption = " -config " + configFile;
            configOption;
            await execute_openssl_no_failure(
                "verify -verbose " + " -CAfile " + q(n(this.caCertificateWithCrl)) + " " + q(n(certificate)),
                options,
            );
        }
    }
}
