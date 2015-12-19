// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2015 - Etienne Rossignon - etienne.rossignon (at) gadz.org
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

"use strict";
Error.stackTraceLimit = 20;
require("requirish")._(module);

var path = require("path");
var fs = require("fs");
var colors = require("colors");

var async = require("async");
var _ = require("underscore");
var assert = require("better-assert");

var get_fully_qualified_domain_name = require("../lib/misc/hostname").get_fully_qualified_domain_name;
var hostname = require("os").hostname();
var makeApplicationUrn = require("../lib/misc/applicationurn").makeApplicationUrn;

var argv = require('yargs')
    .usage('Usage: $0 [--dev] [--silent] [--force]')
    .boolean("force")
    .boolean("forceCA")
    .boolean("dev")
    .boolean("silent")
    .string("applicationUri")
    .string("prefix")
    .boolean("selfSigned")
    .string("privateKey")
    .argv;


var pki = require("../index");
var toolbox = require("../index").toolbox;
var mkdir             = toolbox.mkdir;
var displayChapter    = toolbox.displayChapter;
var displayTitle      = toolbox.displayTitle;
var displaySubtitle   = toolbox.displaySubtitle;
var find_openssl      = toolbox.find_openssl;
var createCertificate = toolbox.createCertificate;
var createPrivateKey  = toolbox.createPrivateKey;
var getPublicKeyFromPrivateKey = toolbox.getPublicKeyFromPrivateKey;
var make_path         = toolbox.make_path;

toolbox.g_config.silent = argv.silent;




function get_offset_date(date, nb_days) {
    var d = new Date(date.getTime());
    d.setDate(d.getDate() + nb_days);
    return d;
}
var today = new Date();
var yesterday     = get_offset_date(today, -1);
var two_years_ago = get_offset_date(today, -2 * 365);
var next_year     = get_offset_date(today, 365);



var config;

var g_argv = require('yargs')

    .strict()
    .wrap(132)
    // ----------------------------------------------- --demo
    .command("createCA", "create the certificate store", function (yargs, argv) {

        var local_argv = yargs
            .strict().wrap(132)
            .boolean("dev")
            .describe("dev", "create all sort of fancy certificates for dev testing purposes")
            .boolean("force")
            .describe("force", "force creation of certificate by overwriting existing certificate file")
            .boolean("forceCA")
            .describe("forceCA", "force creation of CA material")
            .boolean("silent")
            .describe("silent", "no output")
            .options({
                "PKIRootFolder": {
                    default: ".",
                    alias: "r",
                    demand: true,
                    describe: "folder where to find the PKI",
                    type: "string"
                }
            })
            .argv;
        if (local_argv.help) {
            console.log(yargs.help());
        } else {
            config= readConfiguration(argv);
            displayChapter(" Create CertificateStore");
            createDefaultCertificates(local_argv);
        }
    })
    .command("demo", "create default certificate for node-opcua demos", function (yargs, argv) {

        //xx console.log(yargs.argv);

        var local_argv = yargs
            .strict().wrap(132)
            .boolean("dev")
            .describe("dev", "create all sort of fancy certificates for dev testing purposes")

            .boolean("force")
            .describe("force", "force creation of certificate by overwriting existing certificate file")

            .boolean("forceCA")
            .describe("forceCA", "force creation of CA material")

            .boolean("silent")
            .describe("silent", "no output")

            .usage("$0  demo [--dev] [--silent] [--force]")
            .example("$0  demo -dev")

            .help("help")
            .argv;

        if (local_argv.help) {
            console.log(yargs.help());
        } else {
            //xx console.log(local_argv);
            config= readConfiguration(argv);
            displayChapter(" Create Demo certificates");
            createDefaultCertificates(local_argv);
        }
    })

    // ----------------------------------------------- --new
    .command("new", "create a new certificate", function (yargs, argv) {

        var argv = yargs.strict().wrap(132)
            .options({
                "applicationUri": {
                    alias: "a",
                    demand: true,
                    describe: "the application URI",
                    type: "string"
                },
                "PKIRootFolder": {
                    default: ".",
                    alias: "r",
                    demand: true,
                    describe: "folder where to find the PKI",
                    type: "string"
                },
                "output": {
                    default: "my_certificate.pem",
                    alias: "o",
                    demand: true,
                    describe: "the name of the generated certificate =>",
                    type: "string"
                },
                "selfSigned": {
                    alias: "s",
                    default: false,
                    type: "boolean",
                    describe: "if true, certificate will be self-signed"
                },
                "privateKey": {
                    alias: "p",
                    type: "string",
                    default: "${PKIRootFolder}/own/private_key.pem",
                    describe: "the private key to use to generate certificate"
                }
            });
        config= readConfiguration(argv);
        createCertificateFromCommandLine(argv);

    })
    // ----------------------------------------------- --revoke
    .command("revoke", "revoke a existing certificate", function (yargs, argv) {

        var argv = yargs.strict().wrap(132)
            .help("usage : $0 --revoke  my_certificate.pem")
            .options({});
        config=  readConfiguration(argv);
        revokeCertificateFromCommandLine(argv);
    })
    .help("help")
    .strict()
    .argv;


function readConfiguration(argv) {

    var default_certificateDir = make_path(__dirname, "../certificates/");
    mkdir(default_certificateDir);

    var certificateDir = path.resolve(argv.PKIrootFolder || default_certificateDir);
    assert(fs.existsSync(certificateDir));

    // ---------------------------------------------------------------------------------------------------------------------
    var default_config = path.join(certificateDir, path.basename(__filename, ".js") + "_config.js");

    var default_config_template = path.join(__dirname, path.basename(__filename, ".js") + "_config.example.js");
    if (!fs.existsSync(default_config) && fs.existsSync(default_config_template)) {
        // copy
        console.log(" Creating default config file ".yellow, default_config.cyan);
        fs.writeFileSync(default_config, fs.readFileSync(default_config_template));
    }

    var config = require(default_config);
    console.log(" config = ".yellow);
    _.forEach(config,function(value,key) {
        console.log("   " + key.yellow + " : " + value.toString().cyan);
    });
    // ---------------------------------------------------------------------------------------------------------------------

    config.certificateDir = certificateDir;

    // now overwrite config with other
    config.force         = !!argv.force;
    config.forceCA       = !!argv.forceCA;
    config.isDevelopment = !!argv.dev;

    return config;
}


function __create_default_certificates(base_name, prefix, applicationUri, done) {

    // Bad hack that ensures that paths with spaces are correctly interpreted.
    base_name = "\"" + base_name + "\"";

    assert(_.isFunction(done));

    var key_1024 = make_path(base_name, prefix + "key_1024.pem");
    var public_key_1024 = make_path(base_name, prefix + "public_key_1024.pub");
    var key_2048 = make_path(base_name, prefix + "key_2048.pem");

    console.log(" urn = ", applicationUri);

    function createCertificate(certificate,private_key,applicationUri,startDate,duration,callback) {

        var crs_file = certificate+ ".csr" ;
        // create CSR
        toolbox.createCertificateSigningRequest(crs_file,private_key,function(err){
            ca.signCertificateRequest(certificate,crs_file,{
                applicationUri: applicationUri,
                startDate: startDate,
                duration: duration
            },callback);
        });
    }
    function createSelfSignedCertificate(certificate,private_key,applicationUri,startDate,duration,callback) {

        ca.createSelfSignedCertificate(certificate,private_key,{
            applicationUri: applicationUri,
            startDate: startDate,
            duration: duration
        },callback);
    }
    var tasks1 = [

        createPrivateKey.bind(null, key_1024, 1024),

        getPublicKeyFromPrivateKey.bind(null, key_1024, public_key_1024),

        createPrivateKey.bind(null, key_2048, 2048),

        createCertificate.bind(null, make_path(base_name, prefix + "cert_1024.pem"), key_1024, applicationUri, yesterday, 365),
        createCertificate.bind(null, make_path(base_name, prefix + "cert_2048.pem"), key_2048, applicationUri, yesterday, 365),

        createSelfSignedCertificate.bind(null, make_path(base_name, prefix + "selfsigned_cert_1024.pem"), key_1024, applicationUri, yesterday, 365),
        createSelfSignedCertificate.bind(null, make_path(base_name, prefix + "selfsigned_cert_2048.pem"), key_2048, applicationUri, yesterday, 365)

    ];

    if (config.isDevelopment) {
        var tasks2 = [
            createCertificate.bind(null, make_path(base_name, prefix + "cert_1024_outofdate.pem"), key_1024, applicationUri, two_years_ago, 365),
            createCertificate.bind(null, make_path(base_name, prefix + "cert_2048_outofdate.pem"), key_2048, applicationUri, two_years_ago, 365),

            createCertificate.bind(null, make_path(base_name, prefix + "cert_1024_not_active_yet.pem"), key_1024, applicationUri, next_year, 365),
            createCertificate.bind(null, make_path(base_name, prefix + "cert_2048_not_active_yet.pem"), key_2048, applicationUri, next_year, 365),

            createCertificate.bind(null, make_path(base_name, prefix + "cert_1024_revoked.pem"), key_1024, applicationUri, yesterday, 365),
            revoke_certificate.bind(null, make_path(base_name, prefix + "cert_1024_revoked.pem")),

            createCertificate.bind(null, make_path(base_name, prefix + "cert_2048_revoked.pem"), key_2048, applicationUri, yesterday, 365),
            revoke_certificate.bind(null, make_path(base_name, prefix + "cert_2048_revoked.pem"))
        ];
        tasks1 = tasks1.concat(tasks2);
    }


    async.series(tasks1, done);

}

function create_default_certificates(done) {

    var base_name = config.certificateDir;
    assert(fs.existsSync(base_name));

    var hostname = get_fully_qualified_domain_name();
    console.log("     hostname = ".yellow, hostname.cyan);

    var clientURN = makeApplicationUrn(hostname, "NodeOPCUA-Client");
    var serverURN = makeApplicationUrn(hostname, "NodeOPCUA-Server");
    var discoveryServerURN = makeApplicationUrn(hostname, "NodeOPCUA-DiscoveryServer");

    var task1 = [

        displayTitle.bind(null, "Create  Application Certificate for Server & its private key"),
        __create_default_certificates.bind(null, base_name, "client_", clientURN),

        displayTitle.bind(null, "Create  Application Certificate for Client & its private key"),
        __create_default_certificates.bind(null, base_name, "server_", serverURN),

        displayTitle.bind(null, "Create  Application Certificate for DiscoveryServer & its private key"),
        __create_default_certificates.bind(null, base_name, "discoveryServer_", discoveryServerURN)

    ];
    async.series(task1, done);
}

var ca;
function construct_CertificateAuthority(callback) {

    ca = new pki.CertificateAuthority({ location: config.certificateDir + "/CA" });
    ca.initialize(callback);

}
function createDefaultCertificates(argv) {

    async.series([
        construct_CertificateAuthority.bind(null),
        create_default_certificates.bind(null)
    ], function (err) {
        if (err) {
            console.log("ERROR ".red, err.message);
        }
    });
}


function createCertificateFromCommandLine(argv) {


    //example : node bin\crypto_create_CA.js --new --selfSigned --applicationUri urn:localhost:MyProduct --prefix aa --force
    //example : node bin\crypto_create_CA.js --new --privateKey my_private_key.pem --applicationUri urn:localhost:MyProduct --prefix aa --force

    assert(_.isString(argv.applicationUri), "--new require applicationUri to be specified");
    assert(_.isString(argv.prefix), "--new requires a prefix to be speficied");

    // urn:COMPUTERNAME:PRODUCT
    assert(argv.applicationUri.length < 64, "applicationUri cannot exceed 64 characters");
    var options = {
        applicationUri: argv.applicationUri || makeApplicationUrn(get_fully_qualified_domain_name(), "NodeOPCUA-Server")
    };

    options.prefix = argv.prefix;
    options.privateKey = argv.privateKey;
    options.selfSigned = argv.selfSigned;

    createNewCertificate(options, function () {
        console.log("Done ...");
    });

}

function revokeCertificateFromCommandLine(argv) {

    // example : node bin\crypto_create_CA.js --revoke my_certificate.pem

    var certificate = path.resolve(argv.revoke);
    console.log(" Certificate to revoke : ".yellow, certificate.cyan);
    assert(fs.existsSync(certificate), "cannot find certificate to revoke");

    async.series([
        find_openssl.bind(null),
        revoke_certificate.bind(null, certificate)
    ], function (err) {
        console.log("done ... ", err);
        console.log("\nyou should now publish the new Certificate Revocation List");

    });
}


