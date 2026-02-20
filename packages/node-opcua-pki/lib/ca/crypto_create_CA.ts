/* eslint-disable @typescript-eslint/no-unused-vars */
// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
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
// Error.stackTraceLimit = Infinity;
// tslint:disable:variable-name
// tslint:disable:no-console
// tslint:disable:object-literal-sort-keys
// tslint:disable:no-shadowed-variable

import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import chalk from "chalk";
import { CertificatePurpose, generatePrivateKeyFile, Subject, type SubjectOptions } from "node-opcua-crypto";
import { rimraf } from "rimraf";

import { makeApplicationUrn } from "../misc/applicationurn";
import { extractFullyQualifiedDomainName, getFullyQualifiedDomainName } from "../misc/hostname";
import { CertificateManager, type CreateSelfSignCertificateParam1 } from "../pki/certificate_manager";
import {
    type CreateCertificateSigningRequestWithConfigOptions,
    debugLog,
    displayChapter,
    displaySubtitle,
    displayTitle,
    type Filename,
    g_config,
    type KeySize,
    makePath,
    mkdirRecursiveSync,
    warningLog
} from "../toolbox";
import {
    createCertificateSigningRequestWithOpenSSL,
    dumpCertificate,
    ensure_openssl_installed,
    fingerprint,
    getPublicKeyFromPrivateKey,
    setEnv,
    toDer
} from "../toolbox/with_openssl";
import { CertificateAuthority, defaultSubject } from "./certificate_authority";

const epilog = "Copyright (c) sterfive - node-opcua - 2017-2026";

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
            subject
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
            location: gLocalConfig.PKIFolder
        });
        await certificateManager.initialize();
    }
}

function _displayConfig(config: { [key: string]: { toString: () => string } }) {
    function w(str: string, l: number): string {
        return `${str}                            `.substring(0, l);
    }

    warningLog(chalk.yellow(" configuration = "));

    for (const [key, value] of Object.entries(config)) {
        warningLog(`   ${chalk.yellow(w(key, 30))} : ${chalk.cyan(value.toString())}`);
    }
}

function default_template_content(): string {
    // istanbul ignore next
    if ((process as unknown as { pkg?: { entrypoint: string } }).pkg?.entrypoint) {
        // we are using PKG compiled package !

        // warningLog("___filename", __filename);
        // warningLog("__dirname", __dirname);
        // warningLog("process.pkg.entrypoint", (process as unknown as IReadConfigurationOpts).pkg.entrypoint);
        const a = fs.readFileSync(path.join(__dirname, "../../bin/pki_config.example.js"), "utf8");
        return a;
    }
    function find_default_config_template() {
        const rootFolder = find_module_root_folder();
        let default_config_template = path.join(rootFolder, "bin", `${path.basename(__filename, ".js")}_config.example.js`);

        if (!fs.existsSync(default_config_template)) {
            default_config_template = path.join(__dirname, "..", `${path.basename(__filename, ".js")}_config.example.js`);

            if (!fs.existsSync(default_config_template)) {
                default_config_template = path.join(__dirname, `../bin/${path.basename(__filename, ".js")}_config.example.js`);
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
        if (gLocalConfig?.PKIFolder) {
            str = str.replace("{PKIFolder}", gLocalConfig.PKIFolder);
        }
        str = str.replace("{hostname}", hostname);
        str = str.replace("%FQDN%", fqdn);
        return str;
    }

    function prepare(file: Filename): Filename {
        const tmp = path.resolve(performSubstitution(file));
        return makePath(tmp);
    }

    // ------------------------------------------------------------------------------------------------------------
    certificateDir = argv.root;
    assert(typeof certificateDir === "string");

    certificateDir = prepare(certificateDir);
    mkdirRecursiveSync(certificateDir);
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
            throw new Error(`invalid keysize specified ${v} should be 1024,2048,3072 or 4096`);
        }
        gLocalConfig.keySize = argv.keySize;
    }

    if (argv.validity) {
        gLocalConfig.validity = argv.validity;
    }
    // xx displayConfig(g_config);
    // ------------------------------------------------------------------------------------------------------------
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

    const private_key_file = makePath(base_name, `${prefix}key_${key_length}.pem`);
    const public_key_file = makePath(base_name, `${prefix}public_key_${key_length}.pub`);
    const certificate_file = makePath(base_name, `${prefix}cert_${key_length}.pem`);
    const certificate_file_outofdate = makePath(base_name, `${prefix}cert_${key_length}_outofdate.pem`);
    const certificate_file_not_active_yet = makePath(base_name, `${prefix}cert_${key_length}_not_active_yet.pem`);
    const certificate_revoked = makePath(base_name, `${prefix}cert_${key_length}_revoked.pem`);
    const self_signed_certificate_file = makePath(base_name, `${prefix}selfsigned_cert_${key_length}.pem`);

    const fqdn = getFullyQualifiedDomainName();
    const hostname = os.hostname();
    const dns: string[] = [
        // for conformance reason, localhost shall not be present in the DNS field of COP
        // ***FORBIDEN** "localhost",
        getFullyQualifiedDomainName()
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
        const certificateSigningRequestFile = `${certificate}.csr`;

        const configFile = makePath(base_name, "../certificates/PKI/own/openssl.cnf");

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
        await createCertificateSigningRequestWithOpenSSL(certificateSigningRequestFile, params);

        return await g_certificateAuthority.signCertificateRequest(certificate, certificateSigningRequestFile, {
            applicationUri,
            dns,
            ip,
            startDate,
            validity
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
            validity
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

    displaySubtitle(` create private key :${private_key_file}`);

    await createPrivateKeyIfNotExist(private_key_file, key_length);
    displaySubtitle(` extract public key ${public_key_file} from private key `);
    await getPublicKeyFromPrivateKey(private_key_file, public_key_file);
    displaySubtitle(` create Certificate ${certificate_file}`);

    await createCertificateIfNotExist(certificate_file, private_key_file, applicationUri, yesterday, 365);

    displaySubtitle(` create self signed Certificate ${self_signed_certificate_file}`);

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
                `${applicationUri}Revoked`, // make sure we used a uniq URI here
                yesterday,
                365
            );
            warningLog(" certificate to revoke => ", certificate);
            revoke_certificate(certificate_revoked);
        }
    }
}

async function wrap(func: () => Promise<void>) {
    try {
        await func();
    } catch (err) {
        console.log((err as Error).message);
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

import commandLineArgs from "command-line-args";
import commandLineUsage from "command-line-usage";

const commonOptions = [
    {
        name: "root",
        alias: "r",
        type: String,
        defaultValue: "{CWD}/certificates",
        description: "the location of the Certificate folder"
    },
    {
        name: "CAFolder",
        alias: "c",
        type: String,
        defaultValue: "{root}/CA",
        description: "the location of the Certificate Authority folder"
    },
    { name: "PKIFolder", type: String, defaultValue: "{root}/PKI", description: "the location of the Public Key Infrastructure" },
    { name: "silent", type: Boolean, defaultValue: false, description: "minimize output" },
    {
        name: "privateKey",
        alias: "p",
        type: String,
        defaultValue: "{PKIFolder}/own/private_key.pem",
        description: "the private key to use to generate certificate"
    },
    {
        name: "keySize",
        alias: "k",
        type: Number,
        defaultValue: 2048,
        description: "the private key size in bits (1024|2048|3072|4096)"
    },
    { name: "help", alias: "h", type: Boolean, description: "display this help" }
];

function getOptions(names: string[]) {
    return commonOptions.filter((o) => names.includes(o.name) || o.name === "help" || o.name === "silent");
}

function showHelp(command: string, description: string, options: Record<string, unknown>[], usage?: string) {
    const sections = [
        {
            header: `Command: ${command}`,
            content: description
        },
        {
            header: "Usage",
            content: usage || `$0 ${command} [options]`
        },
        {
            header: "Options",
            optionList: options
        }
    ];
    console.log(commandLineUsage(sections));
}

export async function main(argumentsList: string | string[]) {
    const mainDefinitions = [{ name: "command", defaultOption: true }];
    let mainOptions: commandLineArgs.CommandLineOptions;
    try {
        mainOptions = commandLineArgs(mainDefinitions, { argv: argumentsList as string[], stopAtFirstUnknown: true });
    } catch (err) {
        console.log((err as Error).message);
        return;
    }

    const argv = mainOptions._unknown || [];
    const command = mainOptions.command;

    if (!command || command === "help") {
        console.log(
            commandLineUsage([
                {
                    header: "node-opcua-pki",
                    content: `PKI management for node-opcua\n\n${epilog}`
                },
                {
                    header: "Commands",
                    content: [
                        { name: "demo", summary: "create default certificate for node-opcua demos" },
                        { name: "createCA", summary: "create a Certificate Authority" },
                        { name: "createPKI", summary: "create a Public Key Infrastructure" },
                        { name: "certificate", summary: "create a new certificate" },
                        { name: "revoke <certificateFile>", summary: "revoke a existing certificate" },
                        { name: "csr", summary: "create a certificate signing request" },
                        { name: "sign", summary: "validate a certificate signing request and generate a certificate" },
                        { name: "dump <certificateFile>", summary: "display a certificate" },
                        { name: "toder <pemCertificate>", summary: "convert a certificate to a DER format with finger print" },
                        { name: "fingerprint <certificateFile>", summary: "print the certificate fingerprint" },
                        { name: "version", summary: "display the version number" }
                    ]
                }
            ])
        );
        return;
    }

    if (command === "version") {
        const rootFolder = find_module_root_folder();
        const pkg = JSON.parse(fs.readFileSync(path.join(rootFolder, "package.json"), "utf-8"));
        console.log(pkg.version);
        return;
    }

    if (command === "demo") {
        const optionsDef = [
            ...getOptions(["root", "silent"]),
            { name: "dev", type: Boolean, description: "create all sort of fancy certificates for dev testing purposes" },
            { name: "clean", type: Boolean, description: "Purge existing directory [use with care!]" }
        ];
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help)
            return showHelp(
                "demo",
                "create default certificate for node-opcua demos",
                optionsDef,
                "$0 demo [--dev] [--silent] [--clean]"
            );

        await wrap(async () => {
            await ensure_openssl_installed();
            displayChapter("Create Demo certificates");
            displayTitle("reading configuration");
            await readConfiguration(local_argv as unknown as IReadConfigurationOpts);
            if (local_argv.clean) {
                displayTitle("Cleaning old certificates");
                assert(gLocalConfig);
                const certificateDir = gLocalConfig.certificateDir || "";
                await rimraf(`${certificateDir}/*.pem*`);
                await rimraf(`${certificateDir}/*.pub*`);
                mkdirRecursiveSync(certificateDir);
            }
            displayTitle("create certificates");
            await createDefaultCertificates(local_argv.dev);
            displayChapter("Demo certificates  CREATED");
        });
        return;
    }

    if (command === "createCA") {
        const optionsDef = [
            ...getOptions(["root", "CAFolder", "keySize", "silent"]),
            { name: "subject", type: String, defaultValue: defaultSubject, description: "the CA certificate subject" }
        ];
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help) return showHelp("createCA", "create a Certificate Authority", optionsDef);

        await wrap(async () => {
            await ensure_openssl_installed();
            await readConfiguration(local_argv as unknown as IReadConfigurationOpts);
            await construct_CertificateAuthority(local_argv.subject);
        });
        return;
    }

    if (command === "createPKI") {
        const optionsDef = getOptions(["root", "PKIFolder", "keySize", "silent"]);
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help) return showHelp("createPKI", "create a Public Key Infrastructure", optionsDef);

        await wrap(async () => {
            await readConfiguration(local_argv as unknown as IReadConfigurationOpts);
            await construct_CertificateManager();
        });
        return;
    }

    if (command === "certificate") {
        const optionsDef = [
            ...getOptions(["root", "CAFolder", "PKIFolder", "privateKey", "silent"]),
            {
                name: "applicationUri",
                alias: "a",
                type: String,
                defaultValue: "urn:{hostname}:Node-OPCUA-Server",
                description: "the application URI"
            },
            {
                name: "output",
                alias: "o",
                type: String,
                defaultValue: "my_certificate.pem",
                description: "the name of the generated certificate =>"
            },
            {
                name: "selfSigned",
                alias: "s",
                type: Boolean,
                defaultValue: false,
                description: "if true, certificate will be self-signed"
            },
            { name: "validity", alias: "v", type: Number, description: "the certificate validity in days" },
            {
                name: "dns",
                type: String,
                defaultValue: "{hostname}",
                description: "the list of valid domain name (comma separated)"
            },
            { name: "ip", type: String, defaultValue: "", description: "the list of valid IPs (comma separated)" },
            {
                name: "subject",
                type: String,
                defaultValue: "",
                description: "the certificate subject ( for instance C=FR/ST=Centre/L=Orleans/O=SomeOrganization/CN=Hello )"
            }
        ];
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help || !local_argv.applicationUri || !local_argv.output)
            return showHelp("certificate", "create a new certificate", optionsDef);

        async function command_certificate(local_argv: IReadConfigurationOpts) {
            const selfSigned = !!(local_argv as unknown as { selfSigned?: boolean }).selfSigned;
            if (!selfSigned) {
                await command_full_certificate(local_argv);
            } else {
                await command_selfsigned_certificate(local_argv);
            }
        }

        async function command_selfsigned_certificate(local_argv: IReadConfigurationOpts) {
            const _fqdn = await extractFullyQualifiedDomainName();
            await readConfiguration(local_argv);
            await construct_CertificateManager();

            displaySubtitle(` create self signed Certificate ${gLocalConfig.outputFile}`);
            let subject =
                local_argv.subject && local_argv.subject.length > 1 ? new Subject(local_argv.subject) : gLocalConfig.subject || "";

            subject = JSON.parse(JSON.stringify(subject));

            const params: CreateSelfSignCertificateParam1 = {
                applicationUri: gLocalConfig.applicationUri || "",
                dns: gLocalConfig.dns || [],
                ip: gLocalConfig.ip || [],
                outputFile: gLocalConfig.outputFile || "self_signed_certificate.pem",
                startDate: gLocalConfig.startDate || new Date(),
                subject,
                validity: gLocalConfig.validity || 365
            };

            await certificateManager.createSelfSignedCertificate(params);
        }

        async function command_full_certificate(local_argv: IReadConfigurationOpts) {
            await readConfiguration(local_argv);
            await construct_CertificateManager();
            await construct_CertificateAuthority("");
            assert(fs.existsSync(gLocalConfig.CAFolder || ""), " CA folder must exist");
            gLocalConfig.privateKey = undefined; // use PKI private key
            // create a Certificate Request from the certificate Manager

            gLocalConfig.subject = local_argv.subject && local_argv.subject.length > 1 ? local_argv.subject : gLocalConfig.subject;

            const csr_file = await certificateManager.createCertificateRequest(
                gLocalConfig as Parameters<typeof certificateManager.createCertificateRequest>[0]
            );
            if (!csr_file) {
                return;
            }
            warningLog(" csr_file = ", csr_file);
            const certificate = csr_file.replace(".csr", ".pem");

            if (fs.existsSync(certificate)) {
                throw new Error(` File ${certificate} already exist`);
            }
            await g_certificateAuthority.signCertificateRequest(
                certificate,
                csr_file,
                gLocalConfig as Parameters<typeof g_certificateAuthority.signCertificateRequest>[2]
            );

            assert(typeof gLocalConfig.outputFile === "string");
            fs.writeFileSync(gLocalConfig.outputFile || "", fs.readFileSync(certificate, "ascii"));
        }

        await wrap(async () => await command_certificate(local_argv as unknown as IReadConfigurationOpts));
        return;
    }

    if (command === "revoke") {
        const optionsDef = [{ name: "certificateFile", type: String, defaultOption: true }, ...getOptions(["root", "CAFolder"])];
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help || !local_argv.certificateFile)
            return showHelp(
                "revoke <certificateFile>",
                "revoke a existing certificate",
                optionsDef,
                "$0 revoke my_certificate.pem"
            );

        async function revoke_certificate(certificate: Filename) {
            await g_certificateAuthority.revokeCertificate(certificate, {});
        }

        await wrap(async () => {
            const certificate = path.resolve(local_argv.certificateFile);
            warningLog(chalk.yellow(" Certificate to revoke : "), chalk.cyan(certificate));
            if (!fs.existsSync(certificate)) {
                throw new Error(`cannot find certificate to revoke ${certificate}`);
            }
            await readConfiguration(local_argv as unknown as IReadConfigurationOpts);
            await construct_CertificateAuthority("");
            await revoke_certificate(certificate);
            warningLog("done ... ");
            warningLog("  crl = ", g_certificateAuthority.revocationList);
            warningLog("\nyou should now publish the new Certificate Revocation List");
        });
        return;
    }

    if (command === "csr") {
        const optionsDef = [
            ...getOptions(["root", "PKIFolder", "privateKey", "silent"]),
            {
                name: "applicationUri",
                alias: "a",
                type: String,
                defaultValue: "urn:{hostname}:Node-OPCUA-Server",
                description: "the application URI"
            },
            {
                name: "output",
                alias: "o",
                type: String,
                defaultValue: "my_certificate_signing_request.csr",
                description: "the name of the generated signing_request"
            },
            {
                name: "dns",
                type: String,
                defaultValue: "{hostname}",
                description: "the list of valid domain name (comma separated)"
            },
            { name: "ip", type: String, defaultValue: "", description: "the list of valid IPs (comma separated)" },
            {
                name: "subject",
                type: String,
                defaultValue: "/CN=Certificate",
                description: "the certificate subject ( for instance /C=FR/ST=Centre/L=Orleans/O=SomeOrganization/CN=Hello )"
            }
        ];
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help) return showHelp("csr", "create a certificate signing request", optionsDef);

        await wrap(async () => {
            await readConfiguration(local_argv as unknown as IReadConfigurationOpts);
            if (!fs.existsSync(gLocalConfig.PKIFolder || "")) {
                warningLog("PKI folder must exist");
            }
            await construct_CertificateManager();
            if (!gLocalConfig.outputFile || fs.existsSync(gLocalConfig.outputFile)) {
                throw new Error(` File ${gLocalConfig.outputFile} already exist`);
            }
            gLocalConfig.privateKey = undefined; // use PKI private key
            // create a Certificate Request from the certificate Manager

            gLocalConfig.subject = local_argv.subject && local_argv.subject.length > 1 ? local_argv.subject : gLocalConfig.subject;

            const internal_csr_file = await certificateManager.createCertificateRequest(
                gLocalConfig as Parameters<typeof certificateManager.createCertificateRequest>[0]
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
        return;
    }

    if (command === "sign") {
        const optionsDef = [
            ...getOptions(["root", "CAFolder", "silent"]),
            { name: "csr", alias: "i", type: String, defaultValue: "my_certificate_signing_request.csr", description: "the csr" },
            {
                name: "output",
                alias: "o",
                type: String,
                defaultValue: "my_certificate.pem",
                description: "the name of the generated certificate"
            },
            { name: "validity", alias: "v", type: Number, defaultValue: 365, description: "the certificate validity in days" }
        ];
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help || !local_argv.csr || !local_argv.output)
            return showHelp("sign", "validate a certificate signing request and generate a certificate", optionsDef);

        await wrap(async () => {
            await readConfiguration(local_argv as unknown as IReadConfigurationOpts);
            if (!fs.existsSync(gLocalConfig.CAFolder || "")) {
                throw new Error(`CA folder must exist:${gLocalConfig.CAFolder}`);
            }
            await construct_CertificateAuthority("");
            const csr_file: string = path.resolve((local_argv as unknown as { csr?: string }).csr || "");
            if (!fs.existsSync(csr_file)) {
                throw new Error(`Certificate signing request doesn't exist: ${csr_file}`);
            }
            const certificate = path.resolve(local_argv.output || csr_file.replace(".csr", ".pem"));
            if (fs.existsSync(certificate)) {
                throw new Error(` File ${certificate} already exist`);
            }

            await g_certificateAuthority.signCertificateRequest(
                certificate,
                csr_file,
                gLocalConfig as Parameters<typeof g_certificateAuthority.signCertificateRequest>[2]
            );

            assert(typeof gLocalConfig.outputFile === "string");
            fs.writeFileSync(gLocalConfig.outputFile || "", fs.readFileSync(certificate, "ascii"));
        });
        return;
    }

    if (command === "dump") {
        const optionsDef = [
            { name: "certificateFile", type: String, defaultOption: true },
            { name: "help", alias: "h", type: Boolean }
        ];
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help || !local_argv.certificateFile)
            return showHelp("dump <certificateFile>", "display a certificate", optionsDef);

        await wrap(async () => {
            const data = await dumpCertificate(local_argv.certificateFile);
            warningLog(data);
        });
        return;
    }

    if (command === "toder") {
        const optionsDef = [
            { name: "pemCertificate", type: String, defaultOption: true },
            { name: "help", alias: "h", type: Boolean }
        ];
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help || !local_argv.pemCertificate)
            return showHelp("toder <pemCertificate>", "convert a certificate to a DER format with finger print", optionsDef);

        await wrap(async () => {
            await toDer(local_argv.pemCertificate);
        });
        return;
    }

    if (command === "fingerprint") {
        const optionsDef = [
            { name: "certificateFile", type: String, defaultOption: true },
            { name: "help", alias: "h", type: Boolean }
        ];
        const local_argv = commandLineArgs(optionsDef, { argv });
        if (local_argv.help || !local_argv.certificateFile)
            return showHelp("fingerprint <certificateFile>", "print the certificate fingerprint", optionsDef);

        await wrap(async () => {
            const certificate = local_argv.certificateFile;
            const data = await fingerprint(certificate);
            if (!data) return;
            const s = data.split("=")[1].split(":").join("").trim();
            warningLog(s);
        });
        return;
    }

    console.log(`Unknown command: ${command}`);
}
