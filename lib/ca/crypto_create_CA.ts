/* eslint-disable @typescript-eslint/no-unused-vars */
// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2023 - Sterfive.com
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
// Error.stackTraceLimit = Infinity;
// tslint:disable:variable-name
// tslint:disable:no-console
// tslint:disable:object-literal-sort-keys
// tslint:disable:no-shadowed-variable

import * as assert from "assert";
import * as chalk from "chalk";
import * as rimraf from "rimraf";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { callbackify, promisify } from "util";
import { CertificatePurpose, Subject, SubjectOptions, generatePrivateKeyFile } from "node-opcua-crypto";
// see https://github.com/yargs/yargs/issues/781
import * as commands from "yargs";

import { makeApplicationUrn } from "../misc/applicationurn";
import { extractFullyQualifiedDomainName, getFullyQualifiedDomainName } from "../misc/hostname";
import { CertificateAuthority, defaultSubject } from "./certificate_authority";
import { CertificateManager, CreateSelfSignCertificateParam1 } from "../pki/certificate_manager";
import {
    ErrorCallback,
    Filename,
    KeySize,
    CreateCertificateSigningRequestWithConfigOptions,
    displayChapter,
    displaySubtitle,
    displayTitle,
    g_config,
    make_path,
    mkdir,
    debugLog,
    warningLog,
} from "../toolbox";
import {
    getPublicKeyFromPrivateKey,
    setEnv,
    toDer,
    dumpCertificate,
    ensure_openssl_installed,
    fingerprint,
} from "../toolbox/with_openssl";
import { createCertificateSigningRequestAsync } from "../toolbox/with_openssl";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { hideBin } = require("yargs/helpers");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const argv = require("yargs/yargs")(hideBin(process.argv));

const epilog = "Copyright (c) sterfive - node-opcua - 2017-2023";

// ------------------------------------------------- some useful dates
function get_offset_date(date: Date, nbDays: number): Date {
    const d = new Date(date.getTime());
    d.setDate(d.getDate() + nbDays);
    return d;
}

const today = new Date();
const yesterday = get_offset_date(today, -1);
const two_years_ago = get_offset_date(today, -2 * 365);
const next_year = get_offset_date(today, 365);

interface LocalConfig {
    CAFolder?: string;
    PKIFolder?: string;

    keySize?: KeySize;

    subject?: SubjectOptions | string;

    certificateDir?: Filename;

    privateKey?: Filename;

    applicationUri?: string;

    outputFile?: string;

    altNames?: string[];
    dns?: string[];
    ip?: string[];

    startDate?: Date;
    validity?: number;
}

let gLocalConfig: LocalConfig = {};

let g_certificateAuthority: CertificateAuthority; // the Certificate Authority

/***
 *
 *
 * prerequisites :
 *   g_config.CAFolder : the folder of the CA
 */
async function construct_CertificateAuthority(subject: string) {
    // verify that g_config file has been loaded
    assert(typeof gLocalConfig.CAFolder === "string", "expecting a CAFolder in config");
    assert(typeof gLocalConfig.keySize === "number", "expecting a keySize in config");

    if (!g_certificateAuthority) {
        g_certificateAuthority = new CertificateAuthority({
            keySize: gLocalConfig.keySize,
            location: gLocalConfig.CAFolder,
            subject,
        });
        await g_certificateAuthority.initialize();
    }
}

let certificateManager: CertificateManager; // the Certificate Manager
/***
 *
 *
 * prerequisites :
 *   g_config.PKIFolder : the folder of the PKI
 */
async function construct_CertificateManager() {
    assert(typeof gLocalConfig.PKIFolder === "string", "expecting a PKIFolder in config");

    if (!certificateManager) {
        certificateManager = new CertificateManager({
            keySize: gLocalConfig.keySize,
            location: gLocalConfig.PKIFolder,
        });
        await certificateManager.initialize();
    }
}

function displayConfig(config: { [key: string]: { toString: () => string } }) {
    function w(str: string, l: number): string {
        return (str + "                            ").substring(0, l);
    }

    warningLog(chalk.yellow(" configuration = "));

    for (const [key, value] of Object.entries(config)) {
        warningLog("   " + chalk.yellow(w(key, 30)) + " : " + chalk.cyan(value.toString()));
    }
}

function default_template_content(): string {
    // istanbul ignore next
    if ((process as any).pkg && (process as any).pkg.entrypoint) {
        // we are using PKG compiled package !

        // warningLog("___filename", __filename);
        // warningLog("__dirname", __dirname);
        // warningLog("process.pkg.entrypoint", (process as any).pkg.entrypoint);
        const a = fs.readFileSync(path.join(__dirname, "../../bin/crypto_create_CA_config.example.js"), "utf8");
        return a;
    }
    function find_default_config_template() {
        const rootFolder = find_module_root_folder();
        let default_config_template = path.join(rootFolder, "bin", path.basename(__filename, ".js") + "_config.example.js");

        if (!fs.existsSync(default_config_template)) {
            default_config_template = path.join(__dirname, "..", path.basename(__filename, ".js") + "_config.example.js");

            if (!fs.existsSync(default_config_template)) {
                default_config_template = path.join(__dirname, "../bin/" + path.basename(__filename, ".js") + "_config.example.js");
            }
        }
        return default_config_template;
    }
    const default_config_template = find_default_config_template();
    assert(fs.existsSync(default_config_template));
    const default_config_template_content = fs.readFileSync(default_config_template, "utf8");
    return default_config_template_content;
}

/**
 *
 */
function find_module_root_folder() {
    let rootFolder = path.join(__dirname);

    for (let i = 0; i < 4; i++) {
        if (fs.existsSync(path.join(rootFolder, "package.json"))) {
            return rootFolder;
        }
        rootFolder = path.join(rootFolder, "..");
    }

    assert(fs.existsSync(path.join(rootFolder, "package.json")), "root folder must have a package.json file");
    return rootFolder;
}

interface IReadConfigurationOpts {
    root: string;
    silent?: boolean;
    subject?: string;
    CAFolder?: string;
    PKIFolder?: string;
    privateKey?: string;
    applicationUri?: string;
    output?: string;
    altNames?: string;
    dns?: string;
    ip?: string;
    keySize?: KeySize;
    validity?: number;
}
interface IReadConfigurationOpts2 extends IReadConfigurationOpts {
    clean: boolean;
    dev: boolean;
}
interface IReadConfigurationOpts3 extends IReadConfigurationOpts {
    subject: string;
}
interface IReadConfigurationOpts4 extends IReadConfigurationOpts {
    selfSigned: boolean;
}

interface IReadConfigurationOpts5 extends IReadConfigurationOpts {
    certificateFile: string;
}

/* eslint complexity:off, max-statements:off */
async function readConfiguration(argv: IReadConfigurationOpts) {
    if (argv.silent) {
        g_config.silent = true;
    } else {
        g_config.silent = false;
    }

    const fqdn = await extractFullyQualifiedDomainName();
    const hostname = os.hostname();
    let certificateDir: string;

    function performSubstitution(str: string): string {
        str = str.replace("{CWD}", process.cwd());
        if (certificateDir) {
            str = str.replace("{root}", certificateDir);
        }
        if (gLocalConfig && gLocalConfig.PKIFolder) {
            str = str.replace("{PKIFolder}", gLocalConfig.PKIFolder);
        }
        str = str.replace("{hostname}", hostname);
        str = str.replace("%FQDN%", fqdn);
        return str;
    }

    function prepare(file: Filename): Filename {
        const tmp = path.resolve(performSubstitution(file));
        return make_path(tmp);
    }

    // ------------------------------------------------------------------------------------------------------------
    certificateDir = argv.root;
    assert(typeof certificateDir === "string");

    certificateDir = prepare(certificateDir);
    mkdir(certificateDir);
    assert(fs.existsSync(certificateDir));

    // ------------------------------------------------------------------------------------------------------------
    const default_config = path.join(certificateDir, "config.js");

    if (!fs.existsSync(default_config)) {
        // copy
        debugLog(chalk.yellow(" Creating default g_config file "), chalk.cyan(default_config));
        const default_config_template_content = default_template_content();
        fs.writeFileSync(default_config, default_config_template_content);
    } else {
        debugLog(chalk.yellow(" using  g_config file "), chalk.cyan(default_config));
    }
    if (!fs.existsSync(default_config)) {
        debugLog(chalk.redBright(" cannot find config file ", default_config));
    }

    // see http://stackoverflow.com/questions/94445/using-openssl-what-does-unable-to-write-random-state-mean
    // set random file to be random.rnd in the same folder as the g_config file
    const defaultRandomFile = path.join(path.dirname(default_config), "random.rnd");
    setEnv("RANDFILE", defaultRandomFile);

    /* eslint global-require: 0*/
    gLocalConfig = require(default_config);

    gLocalConfig.subject = new Subject(gLocalConfig.subject || "");

    // if subject is provided on the command line , it has hight priority
    if (argv.subject) {
        gLocalConfig.subject = new Subject(argv.subject);
    }

    // istanbul ignore next
    if (!gLocalConfig.subject.commonName) {
        throw new Error("subject must have a Common Name");
    }

    gLocalConfig.certificateDir = certificateDir;

    // ------------------------------------------------------------------------------------------------------------
    let CAFolder = argv.CAFolder || path.join(certificateDir, "CA");
    CAFolder = prepare(CAFolder);
    gLocalConfig.CAFolder = CAFolder;

    // ------------------------------------------------------------------------------------------------------------
    gLocalConfig.PKIFolder = path.join(gLocalConfig.certificateDir, "PKI");
    if (argv.PKIFolder) {
        gLocalConfig.PKIFolder = prepare(argv.PKIFolder);
    }
    gLocalConfig.PKIFolder = prepare(gLocalConfig.PKIFolder);
    if (argv.privateKey) {
        gLocalConfig.privateKey = prepare(argv.privateKey);
    }

    if (argv.applicationUri) {
        gLocalConfig.applicationUri = performSubstitution(argv.applicationUri);
    }

    if (argv.output) {
        gLocalConfig.outputFile = argv.output;
    }

    gLocalConfig.altNames = [];
    if (argv.altNames) {
        gLocalConfig.altNames = argv.altNames.split(";");
    }
    gLocalConfig.dns = [getFullyQualifiedDomainName()];
    if (argv.dns) {
        gLocalConfig.dns = argv.dns.split(",").map(performSubstitution);
    }
    gLocalConfig.ip = [];
    if (argv.ip) {
        gLocalConfig.ip = argv.ip.split(",");
    }
    if (argv.keySize) {
        const v = argv.keySize;
        if (v !== 1024 && v !== 2048 && v !== 3072 && v !== 4096) {
            throw new Error("invalid keysize specified " + v + " should be 1024,2048,3072 or 4096");
        }
        gLocalConfig.keySize = argv.keySize;
    }

    if (argv.validity) {
        gLocalConfig.validity = argv.validity;
    }
    // xx displayConfig(g_config);
    // ------------------------------------------------------------------------------------------------------------
}

interface OptionMap {
    [key: string]: commands.Options;
}

function add_standard_option(options: OptionMap, optionName: string) {
    switch (optionName) {
        case "root":
            options.root = {
                alias: "r",
                type: "string",
                default: "{CWD}/certificates",
                describe: "the location of the Certificate folder",
            };
            break;

        case "CAFolder":
            options.CAFolder = {
                alias: "c",
                type: "string",
                default: "{root}/CA",
                describe: "the location of the Certificate Authority folder",
            };
            break;

        case "PKIFolder":
            options.PKIFolder = {
                type: "string",
                default: "{root}/PKI",
                describe: "the location of the Public Key Infrastructure",
            };
            break;

        case "silent":
            options.silent = {
                alias: "s",
                type: "boolean",
                default: false,
                describe: "minimize output",
            };
            break;

        case "privateKey":
            options.privateKey = {
                alias: "p",
                type: "string",
                default: "{PKIFolder}/own/private_key.pem",
                describe: "the private key to use to generate certificate",
            };
            break;

        case "keySize":
            options.keySize = {
                alias: ["k", "keyLength"],
                type: "number",
                default: 2048,
                describe: "the private key size in bits (1024|2048|3072|4096)",
            };
            break;
        default:
            throw Error("Unknown option  " + optionName);
    }
}

function on_completion(err: Error | null | undefined, done: ErrorCallback) {
    assert(typeof done === "function", "expecting function");
    // istanbul ignore next
    if (err) {
        warningLog(chalk.redBright("ERROR : ") + err.message);
    }
    done();
}

async function createDefaultCertificate(
    base_name: string,
    prefix: string,
    key_length: KeySize,
    applicationUri: string,
    dev: boolean
) {
    // possible key length in bits
    assert(key_length === 1024 || key_length === 2048 || key_length === 3072 || key_length === 4096);

    const private_key_file = make_path(base_name, prefix + "key_" + key_length + ".pem");
    const public_key_file = make_path(base_name, prefix + "public_key_" + key_length + ".pub");
    const certificate_file = make_path(base_name, prefix + "cert_" + key_length + ".pem");
    const certificate_file_outofdate = make_path(base_name, prefix + "cert_" + key_length + "_outofdate.pem");
    const certificate_file_not_active_yet = make_path(base_name, prefix + "cert_" + key_length + "_not_active_yet.pem");
    const certificate_revoked = make_path(base_name, prefix + "cert_" + key_length + "_revoked.pem");
    const self_signed_certificate_file = make_path(base_name, prefix + "selfsigned_cert_" + key_length + ".pem");

    const fqdn = getFullyQualifiedDomainName();
    const hostname = os.hostname();
    const dns: string[] = [
        // for conformance reason, localhost shall not be present in the DNS field of COP
        // ***FORBIDEN** "localhost",
        getFullyQualifiedDomainName(),
    ];
    if (hostname !== fqdn) {
        dns.push(hostname);
    }

    const ip: string[] = [];

    async function createCertificateIfNotExist(
        certificate: Filename,
        private_key: Filename,
        applicationUri: string,
        startDate: Date,
        validity: number
    ): Promise<string> {
        // istanbul ignore next
        if (fs.existsSync(certificate)) {
            warningLog(chalk.yellow("         certificate"), chalk.cyan(certificate), chalk.yellow(" already exists => skipping"));
            return "";
        } else {
            return await createCertificate(certificate, private_key, applicationUri, startDate, validity);
        }
    }

    async function createCertificate(
        certificate: Filename,
        privateKey: Filename,
        applicationUri: string,
        startDate: Date,
        validity: number
    ): Promise<string> {
        const certificateSigningRequestFile = certificate + ".csr";

        const configFile = make_path(base_name, "../certificates/PKI/own/openssl.cnf");

        const dns = [os.hostname()];
        const ip = ["127.0.0.1"];

        const params: CreateCertificateSigningRequestWithConfigOptions = {
            applicationUri,
            privateKey,
            rootDir: ".",
            configFile,
            dns,
            ip,
            purpose: CertificatePurpose.ForApplication
        };

        // create CSR
        await createCertificateSigningRequestAsync(certificateSigningRequestFile, params);

        return await g_certificateAuthority.signCertificateRequest(certificate, certificateSigningRequestFile, {
            applicationUri,
            dns,
            ip,
            startDate,
            validity,
        });
    }

    async function createSelfSignedCertificate(
        certificate: Filename,
        private_key: Filename,
        applicationUri: string,
        startDate: Date,
        validity: number
    ) {
        await g_certificateAuthority.createSelfSignedCertificate(certificate, private_key, {
            applicationUri,
            dns,
            ip,
            startDate,
            validity,
        });
    }

    async function revoke_certificate(certificate: Filename) {
        await g_certificateAuthority.revokeCertificate(certificate, {});
    }

    async function createPrivateKeyIfNotExist(privateKey: Filename, keyLength: KeySize) {
        if (fs.existsSync(privateKey)) {
            warningLog(chalk.yellow("         privateKey"), chalk.cyan(privateKey), chalk.yellow(" already exists => skipping"));
            return;
        } else {
            await generatePrivateKeyFile(privateKey, keyLength);
        }
    }

    displaySubtitle(" create private key :" + private_key_file);

    await createPrivateKeyIfNotExist(private_key_file, key_length);
    displaySubtitle(" extract public key " + public_key_file + " from private key ");
    await promisify(getPublicKeyFromPrivateKey)(private_key_file, public_key_file);
    displaySubtitle(" create Certificate " + certificate_file);

    await createCertificateIfNotExist(certificate_file, private_key_file, applicationUri, yesterday, 365);

    displaySubtitle(" create self signed Certificate " + self_signed_certificate_file);

    if (fs.existsSync(self_signed_certificate_file)) {
        // self_signed certificate already exists
        return;
    }
    await createSelfSignedCertificate(self_signed_certificate_file, private_key_file, applicationUri, yesterday, 365);

    if (dev) {
        await createCertificateIfNotExist(certificate_file_outofdate, private_key_file, applicationUri, two_years_ago, 365);

        await createCertificateIfNotExist(certificate_file_not_active_yet, private_key_file, applicationUri, next_year, 365);

        if (!fs.existsSync(certificate_revoked)) {
            // self_signed certificate already exists
            const certificate = await createCertificateIfNotExist(
                certificate_revoked,
                private_key_file,
                applicationUri + "Revoked", // make sure we used a uniq URI here
                yesterday,
                365
            );
            warningLog(" certificate to revoke => ", certificate);
            revoke_certificate(certificate_revoked);
        }
    }
}

// tslint:disable-next-line:no-empty
let done: ErrorCallback = (err?: Error | null) => {
    /** */
};

async function wrap(func: () => Promise<void>) {
    try {
        await func();
    } catch (err) {
        on_completion(err as Error, () => {
            /** */
        });
    }
}

async function create_default_certificates(dev: boolean) {
    assert(gLocalConfig);
    const base_name = gLocalConfig.certificateDir || "";
    assert(fs.existsSync(base_name));

    let clientURN: string;
    let serverURN: string;
    let discoveryServerURN: string;
    wrap(async () => {
        await extractFullyQualifiedDomainName();
        const hostname = os.hostname();
        const fqdn = getFullyQualifiedDomainName();
        warningLog(chalk.yellow("     hostname = "), chalk.cyan(hostname));
        warningLog(chalk.yellow("     fqdn     = "), chalk.cyan(fqdn));
        clientURN = makeApplicationUrn(hostname, "NodeOPCUA-Client");
        serverURN = makeApplicationUrn(hostname, "NodeOPCUA-Server");
        discoveryServerURN = makeApplicationUrn(hostname, "NodeOPCUA-DiscoveryServer");

        displayTitle("Create  Application Certificate for Server & its private key");
        await createDefaultCertificate(base_name, "client_", 1024, clientURN, dev);
        await createDefaultCertificate(base_name, "client_", 2048, clientURN, dev);
        await createDefaultCertificate(base_name, "client_", 3072, clientURN, dev);
        await createDefaultCertificate(base_name, "client_", 4096, clientURN, dev);

        displayTitle("Create  Application Certificate for Client & its private key");
        await createDefaultCertificate(base_name, "server_", 1024, serverURN, dev);
        await createDefaultCertificate(base_name, "server_", 2048, serverURN, dev);
        await createDefaultCertificate(base_name, "server_", 3072, serverURN, dev);
        await createDefaultCertificate(base_name, "server_", 4096, serverURN, dev);

        displayTitle("Create  Application Certificate for DiscoveryServer & its private key");
        await createDefaultCertificate(base_name, "discoveryServer_", 1024, discoveryServerURN, dev);
        await createDefaultCertificate(base_name, "discoveryServer_", 2048, discoveryServerURN, dev);
        await createDefaultCertificate(base_name, "discoveryServer_", 3072, discoveryServerURN, dev);
        await createDefaultCertificate(base_name, "discoveryServer_", 4096, discoveryServerURN, dev);
    });
}

async function createDefaultCertificates(dev: boolean) {
    await construct_CertificateAuthority("");
    await construct_CertificateManager();
    await create_default_certificates(dev);
}

assert(typeof done === "function");
argv
    .strict()
    .wrap(132)
    .command(
        "demo",
        "create default certificate for node-opcua demos",
        (yargs: commands.Argv) => {
            const options: { [key: string]: commands.Options } = {};
            options.dev = {
                type: "boolean",
                describe: "create all sort of fancy certificates for dev testing purposes",
            };
            options.clean = {
                type: "boolean",
                describe: "Purge existing directory [use with care!]",
            };

            add_standard_option(options, "silent");
            add_standard_option(options, "root");

            const local_argv = yargs
                .strict()
                .wrap(132)
                .options(options)
                .usage("$0  demo [--dev] [--silent] [--clean]")
                .example("$0  demo --dev", "create a set of demo certificates")
                .help("help").argv;

            return local_argv;
        },
        (local_argv: IReadConfigurationOpts2) => {
            wrap(async () => {
                await promisify(ensure_openssl_installed)();
                displayChapter("Create Demo certificates");
                displayTitle("reading configuration");
                await readConfiguration(local_argv);
                if (local_argv.clean) {
                    displayTitle("Cleaning old certificates");
                    assert(gLocalConfig);
                    const certificateDir = gLocalConfig.certificateDir || "";
                    await promisify(rimraf)(certificateDir + "/*.pem*");
                    await promisify(rimraf)(certificateDir + "/*.pub*");
                    await promisify(mkdir)(certificateDir);
                }
                displayTitle("create certificates");
                await createDefaultCertificates(local_argv.dev);
                displayChapter("Demo certificates  CREATED");
            });
        }
    )

    .command(
        "createCA",
        "create a Certificate Authority",
        /* builder*/ (yargs: commands.Argv) => {
            const options: OptionMap = {
                subject: {
                    default: defaultSubject,
                    type: "string",
                    describe: "the CA certificate subject",
                },
            };

            add_standard_option(options, "root");
            add_standard_option(options, "CAFolder");
            add_standard_option(options, "keySize");
            add_standard_option(options, "silent");

            const local_argv = yargs.strict().wrap(132).options(options).help("help").epilog(epilog).argv;
            return local_argv;
        },
        /*handler*/ (local_argv: IReadConfigurationOpts3) => {
            wrap(async () => {
                await promisify(ensure_openssl_installed)();
                await readConfiguration(local_argv);
                await construct_CertificateAuthority(local_argv.subject);
            });
        }
    )
    .command(
        "createPKI",
        "create a Public Key Infrastructure",
        (yargs: commands.Argv) => {
            const options = {};

            add_standard_option(options, "root");
            add_standard_option(options, "PKIFolder");
            add_standard_option(options, "keySize");
            add_standard_option(options, "silent");

            return yargs.strict().wrap(132).options(options).help("help").epilog(epilog).argv;
        },
        (local_argv: IReadConfigurationOpts) => {
            wrap(async () => {
                await readConfiguration(local_argv);
                await construct_CertificateManager();
            });
        }
    )

    // ----------------------------------------------- certificate
    .command(
        "certificate",
        "create a new certificate",
        (yargs: commands.Argv) => {
            const options: OptionMap = {
                applicationUri: {
                    alias: "a",
                    demand: true,
                    describe: "the application URI",
                    default: "urn:{hostname}:Node-OPCUA-Server",
                    type: "string",
                },
                output: {
                    default: "my_certificate.pem",
                    alias: "o",
                    demand: true,
                    describe: "the name of the generated certificate =>",
                    type: "string",
                },
                selfSigned: {
                    alias: "s",
                    default: false,
                    type: "boolean",
                    describe: "if true, certificate will be self-signed",
                },
                validity: {
                    alias: "v",
                    default: null,
                    type: "number",
                    describe: "the certificate validity in days",
                },
                dns: {
                    default: "{hostname}",
                    type: "string",
                    describe: "the list of valid domain name (comma separated)",
                },
                ip: {
                    default: "",
                    type: "string",
                    describe: "the list of valid IPs (comma separated)",
                },
                subject: {
                    default: "",
                    type: "string",
                    describe: "the certificate subject ( for instance C=FR/ST=Centre/L=Orleans/O=SomeOrganization/CN=Hello )",
                },
            };
            add_standard_option(options, "silent");
            add_standard_option(options, "root");
            add_standard_option(options, "CAFolder");
            add_standard_option(options, "PKIFolder");
            add_standard_option(options, "privateKey");

            return yargs.strict().wrap(132).options(options).help("help").epilog(epilog).argv;
        },
        (local_argv: IReadConfigurationOpts4) => {
            async function command_certificate(local_argv: IReadConfigurationOpts4) {
                assert(typeof done === "function");
                const selfSigned = !!local_argv.selfSigned;
                if (!selfSigned) {
                    await command_full_certificate(local_argv);
                } else {
                    await command_selfsigned_certificate(local_argv);
                }
            }

            async function command_selfsigned_certificate(local_argv: IReadConfigurationOpts) {
                const fqdn = await extractFullyQualifiedDomainName();
                await readConfiguration(local_argv);
                await construct_CertificateManager();

                displaySubtitle(" create self signed Certificate " + gLocalConfig.outputFile);
                let subject =
                    local_argv.subject && local_argv.subject.length > 1
                        ? new Subject(local_argv.subject)
                        : gLocalConfig.subject || "";

                subject = JSON.parse(JSON.stringify(subject));

                const params: CreateSelfSignCertificateParam1 = {
                    applicationUri: gLocalConfig.applicationUri || "",
                    dns: gLocalConfig.dns || [],
                    ip: gLocalConfig.ip || [],
                    outputFile: gLocalConfig.outputFile || "self_signed_certificate.pem",
                    startDate: gLocalConfig.startDate || new Date(),
                    subject,
                    validity: gLocalConfig.validity || 365,
                };

                await promisify(certificateManager.createSelfSignedCertificate).call(certificateManager, params);
            }

            async function command_full_certificate(local_argv: IReadConfigurationOpts) {
                await readConfiguration(local_argv);
                await construct_CertificateManager();
                await construct_CertificateAuthority("");
                assert(fs.existsSync(gLocalConfig.CAFolder || ""), " CA folder must exist");
                gLocalConfig.privateKey = undefined; // use PKI private key
                // create a Certificate Request from the certificate Manager

                gLocalConfig.subject =
                    local_argv.subject && local_argv.subject.length > 1 ? local_argv.subject : gLocalConfig.subject;

                const csr_file = await promisify(certificateManager.createCertificateRequest).call(
                    certificateManager,
                    gLocalConfig
                );
                if (!csr_file) {
                    return;
                }
                warningLog(" csr_file = ", csr_file);
                const certificate = csr_file.replace(".csr", ".pem");

                if (fs.existsSync(certificate)) {
                    throw new Error(" File " + certificate + " already exist");
                }
                await promisify(g_certificateAuthority.signCertificateRequest).call(
                    g_certificateAuthority,
                    certificate,
                    csr_file,
                    gLocalConfig
                );

                assert(typeof gLocalConfig.outputFile === "string");
                fs.writeFileSync(gLocalConfig.outputFile || "", fs.readFileSync(certificate, "ascii"));
            }

            wrap(async () => await command_certificate(local_argv));
        }
    )

    // ----------------------------------------------- revoke
    .command(
        "revoke <certificateFile>",
        "revoke a existing certificate",
        (yargs: commands.Argv) => {
            const options: OptionMap = {};
            add_standard_option(options, "root");
            add_standard_option(options, "CAFolder");

            yargs.strict().wrap(132).help("help").usage("$0 revoke  my_certificate.pem").options(options).epilog(epilog);
            return yargs;
        },
        (local_argv: IReadConfigurationOpts5) => {
            function revoke_certificate(certificate: Filename, callback: ErrorCallback) {
                g_certificateAuthority.revokeCertificate(certificate, {}, callback);
            }

            wrap(async () => {
                // example : node bin\crypto_create_CA.js revoke my_certificate.pem
                const certificate = path.resolve(local_argv.certificateFile);
                warningLog(chalk.yellow(" Certificate to revoke : "), chalk.cyan(certificate));
                if (!fs.existsSync(certificate)) {
                    throw new Error("cannot find certificate to revoke " + certificate);
                }
                await readConfiguration(local_argv);
                await construct_CertificateAuthority("");
                await promisify(revoke_certificate)(certificate);
                warningLog("done ... ");
                warningLog("  crl = ", g_certificateAuthority.revocationList);
                warningLog("\nyou should now publish the new Certificate Revocation List");
            });
        }
    )

    .command(
        "csr",
        "create a certificate signing request",
        (yargs: commands.Argv) => {
            const options: OptionMap = {
                applicationUri: {
                    alias: "a",
                    // demand: true,
                    describe: "the application URI",
                    default: "urn:{hostname}:Node-OPCUA-Server",
                    type: "string",
                },
                output: {
                    default: "my_certificate_signing_request.csr",
                    alias: "o",
                    // demand: true,
                    describe: "the name of the generated signing_request",
                    type: "string",
                },
                dns: {
                    default: "{hostname}",
                    type: "string",
                    describe: "the list of valid domain name (comma separated)",
                },
                ip: {
                    default: "",
                    type: "string",
                    describe: "the list of valid IPs (comma separated)",
                },
                subject: {
                    default: "/CN=Certificate",
                    type: "string",
                    describe: "the certificate subject ( for instance /C=FR/ST=Centre/L=Orleans/O=SomeOrganization/CN=Hello )",
                },
            };
            add_standard_option(options, "silent");
            add_standard_option(options, "root");
            add_standard_option(options, "PKIFolder");
            add_standard_option(options, "privateKey");

            return yargs.strict().wrap(132).options(options).help("help").epilog(epilog).argv;
        },
        (local_argv: IReadConfigurationOpts) => {
            wrap(async () => {
                await readConfiguration(local_argv);
                if (!fs.existsSync(gLocalConfig.PKIFolder || "")) {
                    warningLog("PKI folder must exist");
                }
                await construct_CertificateManager();
                if (!gLocalConfig.outputFile || fs.existsSync(gLocalConfig.outputFile)) {
                    throw new Error(" File " + gLocalConfig.outputFile + " already exist");
                }
                gLocalConfig.privateKey = undefined; // use PKI private key
                // create a Certificate Request from the certificate Manager

                gLocalConfig.subject =
                    local_argv.subject && local_argv.subject.length > 1 ? local_argv.subject : gLocalConfig.subject;

                const internal_csr_file = await promisify(certificateManager.createCertificateRequest).call(
                    certificateManager,
                    gLocalConfig
                );
                if (!internal_csr_file) {
                    return;
                }
                if (!gLocalConfig.outputFile) {
                    warningLog("please specify a output file");
                    return;
                }
                const csr = await fs.promises.readFile(internal_csr_file, "utf-8");
                fs.writeFileSync(gLocalConfig.outputFile || "", csr, "utf-8");

                warningLog("Subject        = ", gLocalConfig.subject);
                warningLog("applicationUri = ", gLocalConfig.applicationUri);
                warningLog("altNames       = ", gLocalConfig.altNames);
                warningLog("dns            = ", gLocalConfig.dns);
                warningLog("ip             = ", gLocalConfig.ip);

                warningLog("CSR file = ", gLocalConfig.outputFile);
            });
        }
    )
    .command(
        "sign",
        "validate a certificate signing request and generate a certificate",
        (yargs: commands.Argv) => {
            const options: OptionMap = {
                csr: {
                    alias: "i",
                    default: "my_certificate_signing_request.csr",
                    type: "string",
                    demandOption: true,
                    description: "the csr",
                },
                output: {
                    default: "my_certificate.pem",
                    alias: "o",
                    demand: true,
                    describe: "the name of the generated certificate",
                    type: "string",
                },
                validity: {
                    alias: "v",
                    default: 365,
                    type: "number",
                    describe: "the certificate validity in days",
                },
            };
            add_standard_option(options, "silent");
            add_standard_option(options, "root");
            add_standard_option(options, "CAFolder");
            return yargs.strict().wrap(132).options(options).help("help").epilog(epilog).argv;
        },
        (local_argv: IReadConfigurationOpts) => {
            wrap(async () => {
                /** */
                await readConfiguration(local_argv);
                if (!fs.existsSync(gLocalConfig.CAFolder || "")) {
                    throw new Error("CA folder must exist:" + gLocalConfig.CAFolder);
                }
                await construct_CertificateAuthority("");
                const csr_file: string = path.resolve((local_argv as any).csr || "");
                if (!fs.existsSync(csr_file)) {
                    throw new Error("Certificate signing request doesn't exist: " + csr_file);
                }
                const certificate = path.resolve(local_argv.output || csr_file.replace(".csr", ".pem"));
                if (fs.existsSync(certificate)) {
                    throw new Error(" File " + certificate + " already exist");
                }

                await promisify(g_certificateAuthority.signCertificateRequest).call(
                    g_certificateAuthority,
                    certificate,
                    csr_file,
                    gLocalConfig
                );

                assert(typeof gLocalConfig.outputFile === "string");
                fs.writeFileSync(gLocalConfig.outputFile || "", fs.readFileSync(certificate, "ascii"));
            });
        }
    )
    .command(
        "dump <certificateFile>",
        "display a certificate",
        () => {
            /** */
        },
        (yargs: { certificateFile: string }) => {
            wrap(async () => {
                const data = await promisify(dumpCertificate)(yargs.certificateFile);
                warningLog(data);
            });
        }
    )

    .command(
        "toder <pemCertificate>",
        "convert a certificate to a DER format with finger print",
        () => {
            /** */
        },
        (yargs: { pemCertificate: string }) => {
            wrap(async () => {
                await promisify(toDer)(argv.pemCertificate);
            });
        }
    )

    .command(
        "fingerprint <certificateFile>",
        "print the certificate fingerprint",
        () => {
            /** */
        },
        (local_argv: { certificateFile: string }) => {
            wrap(async () => {
                const certificate = local_argv.certificateFile;
                const data = await promisify(fingerprint)(certificate);
                if (!data) return;
                const s = data.split("=")[1].split(":").join("").trim();
                warningLog(s);
            });
        }
    )
    .command("$0", "help", (yargs: commands.Argv) => {
        warningLog("--help for help");
        return yargs;
    })
    .epilog(epilog)
    .help("help")
    .strict().argv;

export function main(argumentsList: string, _done?: ErrorCallback) {
    if (_done) {
        done = _done;
    }

    commands.parse(argumentsList, (err: Error | null, g_argv: { help: boolean }) => {
        // istanbul ignore next
        if (err) {
            warningLog(" err = ", err);
            warningLog(" use --help for more info");
            setImmediate(() => {
                commands.showHelp();
                done(err);
            });
        } else {
            if (g_argv.help) {
                setImmediate(() => {
                    commands.showHelp();
                    done();
                });
            } else {
                done();
            }
        }
    });
}
