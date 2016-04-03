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

var debugLog = toolbox.debugLog;


function CertificateManager(options) {
    assert(options.hasOwnProperty("location"));
    this.location = toolbox.make_path(options.location);

    toolbox.mkdir(options.location);

    if(!fs.existsSync(this.location)) {
        throw new Error("CertificateManager cannot access location " + this.location);
    }
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

    var self = this;
    var pkiDir = self.location;
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
    fs.writeFileSync(self.configFile, toolbox.configurationFileSimpleTemplate);

    fs.exists(self.privateKey,function(exists) {
        if (!exists) {
            debugLog("generating private key ...");
            toolbox.createPrivateKey(self.privateKey, 2048, function (err) {
                callback(err);
            });
        } else {
            debugLog("private key already exists ... skipping");
            callback();
        }
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

    assert(_.isFunction(callback));

    var self = this;

    params.rootDir = self.rootDir;
    params.configFile = self.configFile;
    params.privateKey = self.privateKey;

    // compose a file name for the request
    var today = (new Date()).getTime().toString();
    var csr_file = path.join(params.rootDir,"own/certs","certificate_" + today + ".csr");

    toolbox.setEnv("OPENSSL_CONF",params.configFile);
    toolbox.setEnv("ALTNAME_URI",    "TOTOTOTO");
    toolbox.setEnv("ALTNAME_DNS",    "");
    toolbox.setEnv("ALTNAME_DNS_1",  "");
    toolbox.setEnv("ALTNAME_DNS_2",  "");
    toolbox.setEnv("ALTNAME_DNS_3",  "");
    toolbox.setEnv("ALTNAME_DNS_4",  "");
    toolbox.setEnv("ALTNAME_IP",     "");


    toolbox.createCertificateSigningRequest(csr_file,self.privateKey,function(err){
        callback(err,csr_file);
    });
};


var crypto_utils = require("node-opcua-crypto").crypto_utils;
var async = require("async");

/**
 *
 * @param callback
 * @private
 */
CertificateManager.prototype._readCertificates = function(callback) {


    var self = this;

    self._trusted_thumb  = {};
    self._rejected_thumb = {};

    function readThumbprint(certificate_filename) {

        var certificate =crypto_utils.readCertificate(certificate_filename);
        var thumbprint = crypto_utils.makeSHA1Thumbprint(certificate).toString("hex");
         return thumbprint;
    }
    function _f(folder,index,callback) {

        var walk    = require('walk');

        var walker  = walk.walk(folder, { followLinks: false });

        walker.on('file', function(root, stat, next) {

            var filename = path.join(root,stat.name);
            var thumbprint = readThumbprint(filename);
            index[thumbprint] = 1;
            next();
        });
        walker.on('end', function() {
            callback();
        });
    }

    self._thumbs = { "rejected": {}, trusted:{}};
    async.series([
        _f.bind(this,path.join(self.rootDir,"trusted"),self._thumbs.trusted),
        _f.bind(this,path.join(self.rootDir,"rejected"),self._thumbs.rejected)
    ],callback)
};


CertificateManager.prototype._getCertificateStatus = function(certificate, callback) {

    var self = this;
    assert(certificate instanceof Buffer);
    var thumbprint = crypto_utils.makeSHA1Thumbprint(certificate).toString("hex");

    debugLog("thumbprint ", thumbprint);

    self._readCertificates(function(err) {

        if (self._thumbs.rejected.hasOwnProperty(thumbprint)) {
            return callback(null,"rejected");
        }
        if (self._thumbs.trusted.hasOwnProperty(thumbprint)) {
            return callback(null,"trusted");
        }
        return callback(null,"unknown");
    });

};
CertificateManager.prototype.getCertificateStatus = function(certificate, callback) {

    var self = this;

    self.initialize(function() {
        self._getCertificateStatus(certificate,function(err,status){
            if (err) { return callback(err); }
            if (status === "unknown" ) {

                assert(certificate instanceof Buffer);
                var thumbprint = crypto_utils.makeSHA1Thumbprint(certificate).toString("hex");
                var certificate_name = path.join(self.rootDir,"rejected",thumbprint + ".pem");

                var pem = crypto_utils.toPem(certificate,"CERTIFICATE");
                fs.writeFile(certificate_name,pem,function(err) {
                    status = "rejected";
                    callback(null,status);
                });
                return;
            }
            callback(null,status);
        });
    });
};

CertificateManager.prototype._moveCertificate = function(certificate,new_status,callback) {
    var self = this;

    assert(certificate instanceof Buffer);
    var thumbprint = crypto_utils.makeSHA1Thumbprint(certificate).toString("hex");

    self.getCertificateStatus(certificate, function(err,status){

        if (status !== new_status) {
            var certificate_src  = path.join(self.rootDir,status,thumbprint + ".pem");
            var certificate_dest = path.join(self.rootDir,new_status,thumbprint + ".pem");

            fs.rename(certificate_src,certificate_dest,function(err){

                delete self._thumbs[status][thumbprint];
                self._thumbs[new_status][thumbprint] = 1;
                callback(err);
            });

        } else {
            callback(null);
        }
    });
};

CertificateManager.prototype.rejectCertificate = function(certificate, callback) {
    this._moveCertificate(certificate,"rejected",callback);
};

CertificateManager.prototype.trustCertificate = function(certificate, callback) {
    this._moveCertificate(certificate,"trusted",callback);
};

