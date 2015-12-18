/* global exports,process,require */
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
var assert = require("better-assert");
var fs = require("fs");
var path = require("path");
var child_process = require("child_process");
var _ = require("underscore");
var byline = require('byline');
var async = require("async");

function quote(str) {
    return "\"" + str + "\"";
}

var openssl_path; // not initialized
exports.g_config = {
    silent: false
};
var displayError = true;

var toolbox = exports;

var install_prerequisite = require("../../bin/install_prerequisite").install_prerequisite;

function find_openssl(callback) {

    if (process.platform === "win32") {
        openssl_path = path.join(__dirname, "../../bin/openssl/openssl.exe");
        if (!fs.existsSync(openssl_path)) {

            return install_prerequisite(function () {
                assert(fs.existsSync(openssl_path));
                console.log("openssl_path", openssl_path);
                callback();
            })
        }
        assert(fs.existsSync(openssl_path));
//xx        console.log("openssl_path", openssl_path);
    } else {
        openssl_path = "openssl"
    }
    async.setImmediate(callback);
}
exports.find_openssl = find_openssl;

function mkdir(folder) {
    if (!fs.existsSync(folder)) {
        if (!exports.g_config.silent) {
            console.log(" .. constructing ".white, folder);
        }
        fs.mkdirSync(folder);
    }
}
exports.mkdir = mkdir;

function setEnv(varName, value) {
    console.log("          set " + varName + " =" + value);
    process.env[varName] = value;

}
exports.setEnv = setEnv;

function execute(cmd, options, callback) {

    assert(_.isFunction(callback));

    ///assert(config.CARootDir && fs.existsSync(option.CARootDir));
    var cwd = options.cwd;
    //xx assert(cwd," Please specify a cwd");

    console.log(" CWD   ".cyan, options.cwd);
    console.log("OPENSSL".cyan, process.env.OPENSSL_CONF);

    if (!exports.g_config.silent) {
        console.log("    " + cmd.cyan.bold);
    }

    var outputs = [];
    var child = child_process.exec(cmd, {cwd: cwd}, function (err) {

        if (err) {
            console.log("        ERR = ".bgWhite.red, err);
        }
        callback(err, outputs.join(""));
    });

    var stream2 = byline(child.stdout);
    stream2.on('data', function (line) {
        outputs.push(line + "\n");
    });

    if (!exports.g_config.silent) {
        var stream1 = byline(child.stderr);
        stream1.on('data', function (line) {
            if (displayError) {
                process.stdout.write("        err " + line.red + "\n");
            }
        });
        stream2.on('data', function (line) {
            process.stdout.write("        out " + line.white.bold + "\n");
        });
    }
}

exports.execute = execute;

exports.execute_no_failure = function execute_no_failure(cmd, callback) {
    execute(cmd, function (err) {
        if (err) {
            console.log(" ERROR : ", err.message);
        }
        callback(null);
    });
};


function ensure_openssl_installed(callback) {

    if (!openssl_path) {
        return find_openssl(function (err) {
            callback(err);
        });
    } else {
        callback();
    }
}

function execute_openssl(cmd, options, callback) {
    ensure_openssl_installed(function (err) {
        if (err) {
            return callback(err);
        }
        execute(quote(openssl_path) + " " + cmd, options, callback);
    });
}
exports.execute_openssl = execute_openssl;

function execute_openssl_no_failure(cmd, options, callback) {
    execute_openssl(cmd, options, function (err, output_string) {
        if (err) {
            console.log(" ERROR : ", err.message);
        }
        callback(null, output_string);
    });
}
exports.execute_openssl_no_failure = execute_openssl_no_failure;

function displayChapter(str, option_callback) {

    var l = "                                                                                               ";
    console.log(l.bgWhite);
    str = ("        " + str + l ).substring(0, l.length);
    console.log(str.bgWhite.cyan);
    console.log(l.bgWhite);
    if (option_callback) {
        option_callback();
    }
}
exports.displayChapter = displayChapter;

function displayTitle(str, option_callback) {

    if (!exports.g_config.silent) {
        console.log("");
        console.log(str.yellow.bold);
        console.log(new Array(str.length + 1).join("=").yellow, "\n");
    }
    if (option_callback) {
        option_callback();
    }
}
exports.displayTitle = displayTitle;

function displaySubtitle(str, option_callback) {

    if (!exports.g_config.silent) {
        console.log("");
        console.log("    " + str.yellow.bold);
        console.log("    " + new Array(str.length + 1).join("-").white, "\n");
    }
    if (option_callback) {
        option_callback();
    }
}
exports.displaySubtitle = displaySubtitle;

exports.make_path = function make_path(folder_name, file_name) {
    folder_name = folder_name.replace(/\"/g, "");
    var s;
    if (file_name) {
        s = path.join(path.normalize(folder_name), file_name);
    } else {
        s = folder_name;
    }
    s = s.replace(/\\/g, "/");
    s = s.replace(/\"/g, "");
    return s;
};

var n = toolbox.make_path;
/**
 *   calculate the public key from private key
 *   openssl rsa -pubout -in private_key.pem
 *
 * @method getPublicKeyFromPrivateKey
 * @param private_key_filename
 * @param public_key_filename
 * @param callback  {Function}
 */
exports.getPublicKeyFromPrivateKey = function getPublicKeyFromPrivateKey(private_key_filename, public_key_filename, callback) {
    assert(fs.existsSync(private_key_filename));
    execute_openssl("rsa -pubout -in " + private_key_filename + " > " + public_key_filename, {}, callback);
};


/**
 * extract public key from a certificate
 *   openssl x509 -pubkey -in certificate.pem -nottext
 *
 * @method getPublicKeyFromCertificate
 * @param certificate_filename
 * @param public_key_filename
 * @param callback
 */
exports.getPublicKeyFromCertificate = function getPublicKeyFromCertificate(certificate_filename, public_key_filename, callback) {
    assert(fs.existsSync(certificate_filename));
    execute("x509 -pubkey -in" + certificate_filename + " -notext  > " + public_key_filename, callback);
};


/**
 * create a RSA PRIVATE KEY
 *
 * @method createPrivateKey
 *
 * @param private_key_filename
 * @param key_length
 * @param callback {Function}
 */
function createPrivateKey(private_key_filename, key_length, callback) {

    assert([1024, 2048, 4096].indexOf(key_length) >= 0);
    if (fs.existsSync(private_key_filename)) {
        if (exports.g_config.force) {
            console.log("private key ", private_key_filename, "  exists => deleted");
            fs.unlinkSync(private_key_filename);
        } else {
            console.log("private key ", private_key_filename, " already exists ");
            return callback();
        }
    }
    execute_openssl("genrsa -out " + private_key_filename + " " + key_length, {}, callback);
}
exports.createPrivateKey = createPrivateKey;


/**
 *
 * @param csr_file
 * @param private_key
 * @param callback
 */
exports.createCertificateSigningRequest = function createCertificateSigningRequest(csr_file, private_key, callback) {

    assert(_.isString(private_key));
    assert(fs.existsSync(private_key), "Private key must exist");
    assert(_.isString(csr_file));

    //process.env.OPENSSL_CONF  ="";
    process.env.ALTNAME_URI   ="";
    process.env.ALTNAME_DNS   ="";
    process.env.ALTNAME_DNS_1 ="";
    process.env.ALTNAME_DNS_2 ="";
    async.series([
        displaySubtitle.bind(null, "- Creating a Certificate Signing Request"),
        execute_openssl.bind(null, "req -text" +
            " -batch -new -key " + n(private_key) + " -out " + n(csr_file), {})
    ], callback);
};



function x509Date(date) {

    var Y = date.getUTCFullYear();
    var M = date.getUTCMonth() + 1;
    var D = date.getUTCDate();
    var h = date.getUTCHours();
    var m = date.getUTCMinutes();
    var s = date.getUTCSeconds();

    function w(s, l) {
        return ("00000" + s).substr(-l, l);
    }

    return w(Y, 4) + w(M, 2) + w(D, 2) + w(h, 2) + w(m, 2) + w(s, 2) + "Z";
}
toolbox.x509Date = x509Date;

function adjustDate(params) {

    params.startDate = params.startDate || new Date();
    assert(params.startDate instanceof Date);

    params.duration = params.duration || 365; // one year

    params.endDate = new Date(params.startDate.getTime());
    params.endDate.setDate(params.startDate.getDate() + params.duration);

    //xx params.endDate = toolbox.x509Date(endDate);
    //xx params.startDate = toolbox.x509Date(startDate);

    assert(params.endDate instanceof Date);
    assert(params.startDate instanceof Date);
    console.log(" start Date ", params.startDate.toUTCString(), toolbox.x509Date(params.startDate));
    console.log(" end   Date ", params.endDate.toUTCString(), toolbox.x509Date(params.endDate));

}
exports.adjustDate = adjustDate;

function adjustApplicationUri(params) {
    var applicationUri = params.applicationUri;
    assert(typeof applicationUri === "string");
    assert(applicationUri.length <= 64, "Openssl doesn't support urn with length greater than 64 ");
}
exports.adjustApplicationUri = adjustApplicationUri;

/**
 * create a certificate issued by the Certification Authority
 * @method createCertificate
 * @param self_signed
 * @param certificate_file
 * @param private_key
 * @param params {Object}
 * @param params.private_key
 * @param params.applicationUri
 * @param params.startDate
 * @param params.duration
 * @param params.rootDir
 * @param callback
 */
function _createCertificateInCA(self_signed, certificate_file, private_key, params, callback) {


}

function check_certificate_filename(certificate_file,params) {
    assert(typeof certificate_file === "string");
    if (fs.existsSync(certificate_file) && !exports.g_config.force) {
        console.log("        certificate ".yellow + certificate_file.cyan + " already exists => do not overwrite".yellow);
        return false;
    }
    return true;
}
exports.check_certificate_filename = check_certificate_filename;

function processAltNames(params) {
    params.dns = params.dns ||[];
    params.ip  = params.ip  ||[];

    toolbox.setEnv("ALTNAME_URI",   params.applicationUri);
    toolbox.setEnv("ALTNAME_DNS",   params.dns[0]|| "");
    toolbox.setEnv("ALTNAME_DNS_1", params.dns[1]|| "");
    toolbox.setEnv("ALTNAME_DNS_2", params.dns[2]|| "");
    toolbox.setEnv("ALTNAME_DNS_3", params.dns[3]|| "");
    toolbox.setEnv("ALTNAME_DNS_4", params.dns[4]|| "");
    toolbox.setEnv("ALTNAME_IP", params.ip[0]||"");
}
exports.processAltNames = processAltNames;


/**
 *
 * @param certificate_file       {String} the certificate filename to generate
 * @param csr_file               {String} the certificate signing request
 * @param params                 {Object}
 * @param params.applicationUri  {String} the applicationUri
 * @param params.startDate       {Date}   startDate of the certificate
 * @param params.duration        {Number} duration in date
 * @param callback               {Function}
 */
exports.signCertificateRequestInCA = function signCertificateRequestInCA(certificate_file, csr_file, params, callback) {

    assert(fs.existsSync(params.configFile));
    if (!check_certificate_filename(certificate_file)){ return callback(); }

    toolbox.adjustDate(params);
    toolbox.adjustApplicationUri(params);
    toolbox.processAltNames(params);

    var options = {cwd: params.rootDir } ;
    var configOption = " -config " + n(params.configFile);
    // this require OPENSSL_CONF to be set
    assert(fs.existsSync(process.env.OPENSSL_CONF));

    var tasks = [];

    tasks.push(displaySubtitle.bind(null, "- then we ask the authority to sign the certificate signing request"));
    tasks.push(execute_openssl.bind(null, "ca " + configOption +
        " -startdate " + toolbox.x509Date(params.startDate) +
        " -enddate " + toolbox.x509Date(params.endDate) +
        " -batch -out " + certificate_file + " -in " + csr_file, options));



    tasks.push(displaySubtitle.bind(null, "- dump the certificate for a check"));
    tasks.push(execute_openssl.bind(null, "x509 -in " + certificate_file + "  -dates -fingerprint -purpose -noout", {}));

    tasks.push(displaySubtitle.bind(null, "- construct CA certificate with CRL"));
    tasks.push(constructCACertificateWithCRL.bind(null));

    // construct certificate chain
    //   concatenate certificate with CA Certificate and revocation list
    tasks.push(displaySubtitle.bind(null, "- construct certificate chain"));
    tasks.push(constructCertificateChain.bind(null, false, certificate_file));


    // todo
    // tasks.push(displaySubtitle.bind(null, "- verify certificate against the root CA"));
    // tasks.push(execute_openssl_no_failure.bind(null, "verify -verbose -CAfile " + config.caCertificate_With_CRL + " " + certificate_file, options));

    async.series(tasks, callback);
};


exports.createSelfSignCertificate = function createSelfSignCertificate(certificate, params, callback) {

    /**
     * note: due to a limitation of openssl ,
     *       it is not possible to control the startDate  of the certificate validity
     *       to acheive this the certificateAuthority tool shall be used.
     */
    assert(fs.existsSync(params.configFile));
    assert(fs.existsSync(params.rootDir));
    assert(fs.existsSync(params.privateKey));

    assert(_.isString(params.applicationUri));
    assert(_.isArray(params.dns));

    processAltNames(params);
    adjustDate(params);

    var subject = "/C=FR/ST=IDF/L=Paris/O=ZZLocal NODE-OPCUA Certificate Authority/CN=ZZNodeOPCUA";

    var certificate_request = certificate + ".csr";

    //xxx var configuration_file = path.join(__dirname,"./toto.conf");
    //xxx exports.setEnv("HOME",__dirname);


    var tasks = [

        displayTitle.bind(null, "Generate a certificate request"),

        // Once the private key is generated a Certificate Signing Request can be generated.
        // The CSR is then used in one of two ways. Ideally, the CSR will be sent to a Certificate Authority, such as
        // Thawte or Verisign who will verify the identity of the requestor and issue a signed certificate.
        // The second option is to self-sign the CSR, which will be demonstrated in the next section
        execute_openssl.bind(null, "req -new" +
            " -text " +
            " -extensions v3_ca" +
//xx          " -extfile " + configuration_file +
            " -key " + n(params.privateKey) +
            " -out " + n(certificate_request) +
            " -subj \"" + subject + "\"", {}),

        //Xx // Step 3: Remove Passphrase from Key
        //Xx execute("cp private/cakey.pem private/cakey.pem.org");
        //Xx execute(openssl_path + " rsa -in private/cakey.pem.org -out private/cakey.pem -passin pass:"+paraphrase);

        displayTitle.bind(null, "Generate Certificate (self-signed)"),
        execute_openssl.bind(null, " x509 -req " +
            " -days " + params.duration +
            " -text " +
            " -extensions v3_ca" +
            " -extfile " + n(params.configFile) +
            " -in " + n(certificate_request) +
            " -signkey " + n(params.privateKey) +
            " -out " + certificate, {})

    ];
    async.series(tasks, callback);
};




function inlineText(f) {
    return f.toString().
    replace(/^[^\/]+\/\*!?/, '').
    replace(/\*\/[^\/]+$/, '');
}

function configurationFile() {
    /*
     #.........DO NOT MODIFY BY HAND .........................
     [ ca ]
     default_ca               = CA_default

     [ CA_default ]
     dir                      = %%ROOT_FOLDER%%            # the main CA folder
     certs                    = $dir/certs                 # where to store certificates
     new_certs_dir            = $dir/certs                 #
     database                 = $dir/index.txt             # the certificate database
     serial                   = $dir/serial                # the serial number counter
     certificate              = $dir/public/cacert.pem     # The root CA certificate
     private_key              = $dir/private/cakey.pem     # the CA private key

     x509_extensions          = usr_cert                   #
     default_days             = 3650                       # default duration : 10 years

     default_md               = sha1
     # default_md             = sha256                      # The default digest algorithm

     preserve                 = no
     policy                   = policy_match

     RANDFILE                 = $dir/private/randfile
     # default_startdate        = YYMMDDHHMMSSZ
     # default_enddate          = YYMMDDHHMMSSZ

     crl_dir                  = $dir/crl
     crl_extensions           = crl_ext
     crl                      = $dir/revocation_list.crl # the Revocation list
     crlnumber                = $dir/crlnumber           # CRL number file
     default_crl_days         = 30
     default_crl_hours        = 24
     #msie_hack

     [ policy_match ]
     countryName              = optional
     stateOrProvinceName      = optional
     localityName             = optional
     organizationName         = optional
     organizationalUnitName   = optional
     commonName               = optional
     emailAddress             = optional

     [ req ]
     default_bits             = 4096                     # Size of keys
     default_keyfile          = key.pem                  # name of generated keys
     distinguished_name       = req_distinguished_name
     attributes               = req_attributes
     x509_extensions          = v3_ca
     #input_password
     #output_password
     string_mask              = nombstr                  # permitted characters
     req_extensions           = v3_req

     [ req_distinguished_name ]
     #0 countryName             = Country Name (2 letter code)
     # countryName_default     = FR
     # countryName_min         = 2
     # countryName_max         = 2
     # stateOrProvinceName     = State or Province Name (full name)
     # stateOrProvinceName_default = Ile de France
     # localityName            = Locality Name (city, district)
     # localityName_default    = Paris
     organizationName          = Organization Name (company)
     organizationName_default  = NodeOPCUA
     # organizationalUnitName  = Organizational Unit Name (department, division)
     # organizationalUnitName_default = R&D
     commonName                = Common Name (hostname, FQDN, IP, or your name)
     commonName_max            = 64
     commonName_default        = NodeOPCUA
     # emailAddress            = Email Address
     # emailAddress_max        = 40
     # emailAddress_default    = node-opcua (at) node-opcua (dot) com

     [ req_attributes ]
     #challengePassword        = A challenge password
     #challengePassword_min    = 4
     #challengePassword_max    = 20
     #unstructuredName         = An optional company name

     [ usr_cert ]
     basicConstraints          = critical, CA:FALSE
     subjectKeyIdentifier      = hash
     authorityKeyIdentifier    = keyid,issuer:always
     #authorityKeyIdentifier    = keyid
     subjectAltName            = @alt_names
     # issuerAltName            = issuer:copy
     nsComment                 = ''OpenSSL Generated Certificate''
     #nsCertType               = client, email, objsign for ''everything including object signing''
     #nsCaRevocationUrl        = http://www.domain.dom/ca-crl.pem
     #nsBaseUrl                =
     #nsRenewalUrl             =
     #nsCaPolicyUrl            =
     #nsSslServerName          =
     keyUsage                  = critical, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign
     extendedKeyUsage          = critical,serverAuth ,clientAuth

     [ v3_req ]
     basicConstraints          = critical, CA:FALSE
     keyUsage                  = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement
     # subjectAltName            = $ENV::ALTNAME
     subjectAltName            = @alt_names
     nsComment                 = "CA Generated by Node-OPCUA Certificate utility using openssl"

     [ alt_names ]
     URI                       = $ENV::ALTNAME_URI
     DNS.0                     = $ENV::ALTNAME_DNS
     DNS.1                     = $ENV::ALTNAME_DNS_1

     [ v3_ca ]
     subjectKeyIdentifier      = hash
     authorityKeyIdentifier    = keyid:always,issuer:always
     # authorityKeyIdentifier    = keyid
     basicConstraints          = CA:TRUE
     keyUsage                  = critical, cRLSign, keyCertSign
     nsComment                 = "CA Certificate generated by Node-OPCUA Certificate utility using openssl"
     #nsCertType                 = sslCA, emailCA
     #subjectAltName             = email:copy
     #issuerAltName              = issuer:copy
     #obj                        = DER:02:03
     crlDistributionPoints     = @crl_info

     [ crl_info ]
     URI.0                     = http://localhost:8900/crl.pem

     [ v3_selfsigned]
     basicConstraints          = critical, CA:FALSE
     keyUsage                  = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyAgreement
     nsComment                 = "Self-signed certificate"
     subjectAltName            = @alt_names

     [ crl_ext ]
     #issuerAltName            = issuer:copy
     authorityKeyIdentifier    = keyid:always,issuer:always
     #authorityInfoAccess       = @issuer_info

     */
}


exports.configurationFileTemplate = inlineText(configurationFile);


/**
 *
 * a minimalist config file for openssl that allows
 * self-signed certificate to be generated.
 *
 */
exports.configurationFileSimpleTemplate = inlineText(function () {
    /*
     distinguished_name       = req_distinguished_name

     [ v3_ca ]
     subjectKeyIdentifier        = hash
     authorityKeyIdentifier      = keyid:always,issuer:always
     # authorityKeyIdentifier    = keyid
     basicConstraints            = CA:TRUE
     keyUsage                    = critical, cRLSign, keyCertSign
     nsComment                   = "SelfSigned Certificate generated by Node-OPCUA Certificate utility using openssl"
     #nsCertType                 = sslCA, emailCA
     #subjectAltName             = email:copy
     #issuerAltName              = issuer:copy
     #obj                        = DER:02:03
     # crlDistributionPoints       = @crl_info
     # [ crl_info ]
     # URI.0                     = http://localhost:8900/crl.pem
     subjectAltName            = @alt_names

     [ alt_names ]
     URI                       = $ENV::ALTNAME_URI
     DNS.0                     = $ENV::ALTNAME_DNS
     DNS.1                     = $ENV::ALTNAME_DNS_1
     DNS.2                     = $ENV::ALTNAME_DNS_2
     DNS.3                     = $ENV::ALTNAME_DNS_3
     DNS.4                     = $ENV::ALTNAME_DNS_4
     IP.0                      = $ENV::ALTNAME_IP

     [ req_distinguished_name ]
     #0 countryName             = Country Name (2 letter code)
     # countryName_default     = FR
     # countryName_min         = 2
     # countryName_max         = 2
     # stateOrProvinceName     = State or Province Name (full name)
     # stateOrProvinceName_default = Ile de France
     # localityName            = Locality Name (city, district)
     # localityName_default    = Paris
     organizationName          = Organization Name (company)
     organizationName_default  = NodeOPCUA
     # organizationalUnitName  = Organizational Unit Name (department, division)
     # organizationalUnitName_default = R&D
     commonName                = Common Name (hostname, FQDN, IP, or your name)
     commonName_max            = 256
     commonName_default        = NodeOPCUA
     # emailAddress            = Email Address
     # emailAddress_max        = 40
     # emailAddress_default    = node-opcua (at) node-opcua (dot) com

     */
});


/**
 *
 * @param certificate {String} - the certificate file in PEM format, file must exist
 * @param callback {Function}
 * @param callback.err    {null|Error}
 * @param callback.output {String} the output string
 */
exports.dumpCertificate = function (certificate, callback) {

    assert(fs.existsSync(certificate));
    assert(_.isFunction(callback));

    execute_openssl("x509 " +
        " -in " + certificate +
        " -text " +
        " -noout", {}, callback);
};

