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
var assert = require("assert");
var fs = require("fs");
var path = require("path");
require("colors");
var _ = require("underscore");

var toolbox = require("./toolbox");
var mkdir = toolbox.mkdir;


function CertificateManager(options) {
    assert(options.hasOwnProperty("location"));
    this.location = toolbox.make_path(options.location);
}


/**
 * @method createCertificateStore
 * @param callback
 *
 *  PKI
 *    +---> trusted
 *    +---> rejected
 *    +---> own
 *           +---> cert
 *           +---> own
 *
 */
CertificateManager.prototype.initialize = function (callback) {


    var pkiDir = this.location;
    mkdir(pkiDir);
    mkdir(path.join(pkiDir, "own"));
    mkdir(path.join(pkiDir, "own/certs"));
    mkdir(path.join(pkiDir, "own/private"));
    mkdir(path.join(pkiDir, "trusted"));
    mkdir(path.join(pkiDir, "rejected"));


    //if (1 || !fs.existsSync(this.configFile)) {
    //    var data = toolbox.configurationFileTemplate;
    //    data = data.replace(/%%ROOT_FOLDER%%/, toolbox.make_path(pkiDir,"own"));
    //    fs.writeFileSync(this.configFile, data);
    //}
    //
    fs.writeFileSync(this.configFile, toolbox.configurationFileSimpleTemplate);

    toolbox.createPrivateKey(this.privateKey, 2048, function (err) {
        callback(err);
    });
};

exports.CertificateManager = CertificateManager;

CertificateManager.prototype.__defineGetter__("configFile", function () {
    return path.join(this.rootDir, "own/openssl.cnf");
});

CertificateManager.prototype.__defineGetter__("rootDir", function () {
    return this.location;
});

CertificateManager.prototype.__defineGetter__("privateKey", function () {
    return path.join(this.rootDir, "own/private/private_key.pem");
});

/**
 *
 * create a self-signed certificate for the CertificateManager private key
 *
 *
 * @param params
 * @param params.applicationUri {String}  the application URI
 * @param params.altNames {String[]} array of alternate names
 * @param callback
 *
 * @example
 */
CertificateManager.prototype.createSelfSignedCertificate = function (params, callback) {

    var self = this;
    assert(_.isString(params.applicationUri));
    assert(fs.existsSync(self.privateKey));

    var certificate_filename = path.join(self.rootDir, "own/certs/self_signed_certificate.pem");

    params.rootDir = self.rootDir;
    params.configFile = self.configFile;
    params.privateKey = self.privateKey;

    toolbox.createSelfSignCertificate(certificate_filename, params, callback);
};

/**
 * create a certificate signing Request for the private key of the Certificate Manager
 * @param params {Object}
 * @param params.applicationUri {Object}
 * @param params.dns {Sttring[]}
 * @param params.ip {Sttring[]}
 *
 * @param callback
 */
CertificateManager.prototype.createCertificateRequest = function(params, callback) {

    var self = this;

    params.rootDir = self.rootDir;
    params.configFile = self.configFile;
    params.privateKey = self.privateKey;

    var certificate_signing_request = path.resolve("tmp.txt");

    toolbox.createCertificateSigningRequest(certificate_signing_request,self.privateKey,function(err){
        callback(err,certificate_signing_request);
    });
};
