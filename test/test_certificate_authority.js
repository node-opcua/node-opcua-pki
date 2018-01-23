/* global: it,describe */


var path = require("path");
var async = require("async");
var fs = require("fs");
require("should");

var pki = require("../index");
var toolbox = pki.toolbox;

var crypto_utils =require("node-opcua-crypto").crypto_utils;
var crypto_explore_certificate=require("node-opcua-crypto").crypto_explore_certificate;

describe("Certificate Authority", function () {


    require("./helpers").beforeTest(this);

    var options = {};
    var self = this;
    before(function () {

        options = {
            location: path.join(self.tmpFolder, "CA"),
            keySize: 2048
        };
    });

    it("should read openssl version", function (done) {

        toolbox.execute_openssl("version", {cwd: "."}, function (err,outputs) {
            outputs = outputs.trim();
            toolbox.openssl_version.should.eql(outputs);
            done(err);
        });
    });

    it("should create a CertificateAuthority", function (done) {

        var ca = new pki.CertificateAuthority(options);

        ca.initialize(function (err) {
            done(err);
        });
    });


});

describe("Signing Certificate with Certificate Authority" ,function(){


    var test =this;

    require("./helpers").beforeTest(this);

    var ca,cm;

    before(function (done) {

        ca = new pki.CertificateAuthority({keySize: 2048,location: path.join(test.tmpFolder, "CA")});
        cm = new pki.CertificateManager({location: path.join(test.tmpFolder, "PI")});

        async.series([
            function(callback){ cm.initialize(callback); },
            function(callback){ ca.initialize(callback); }
        ],done);
    });

    function createCertificateRequest(callback) {

        // let create a certificate request
        var params = {
            applicationUri: "MY:APPLICATION:URI",
            // can only be TODAY due to openssl limitation : startDate: new Date(2010,2,2),
            validity: 365 * 7,
            dns: [
                "localhost",
                "my.domain.com"
            ],
            ip: [
                "192.123.145.121"
            ],
            subject: "/CN=MyCommonName"
        };
        cm.createCertificateRequest(params, function (err, certificate_request) {
            callback(err, certificate_request);
        });

    }

    it("should have a CA Certificate",function(done){
        fs.existsSync(ca.caCertificate).should.eql(true);
        done();
    });

    it("should have a CA Certificate with a CRL",function(done){
        ca.constructCACertificateWithCRL(function() {
            fs.existsSync(ca.caCertificateWithCrl).should.eql(true);
            done();
        });
    });

    it("should sign a Certificate Request", function (done) {


        var self = this;
        self.certificate_request="";

        async.series([

            function(callback) {
                // create a Certificate Signing Request
                createCertificateRequest(function(err,certificate_request) {
                    self.certificate_request = certificate_request;
                    callback(err)
                })
            },

            function (callback) {

                fs.existsSync(self.certificate_request).should.eql(true);

                var certificate_filename = path.join(test.tmpFolder, "sample_certificate.pem");

                var params = {
                    applicationUri:  "BAD SHOULD BE IN REQUEST",
                    startDate: new Date(2011,25,12),
                    validity: 10* 365
                };

                ca.signCertificateRequest(certificate_filename,self.certificate_request,params,function(err, certificate) {
                    //xx console.log("Certificate = ",certificate);
                    fs.existsSync(certificate).should.eql(true);

                    //Serial Number: 4096 (0x1000)

                    var certificateChain = crypto_utils.readCertificate(certificate);

                    var elements = crypto_explore_certificate.split_der(certificateChain);
                    elements.length.should.eql(2);
                    // should have 2 x -----BEGIN CERTIFICATE----- in the chain

                    callback(err);
                });

            },

            function (callback) {
                // should verify that certificate is valid
                // todo
                callback();
            }


        ],done);
    });

    it("T2 - should create various Certificates signed by the CA authority", function (done) {


        var self = this;
        self.certificate_request="";

        var now = new Date();
        var last_year = new Date();
        last_year.setFullYear(now.getFullYear()-1);
        var next_year = (new Date());
        next_year.setFullYear(now.getFullYear()+1);

        function sign(startDate,validity,callback) {

            var a = toolbox.x509Date(startDate) + "_" + validity;

            fs.existsSync(self.certificate_request).should.eql(true);

            var certificate_filename = path.join(test.tmpFolder, "sample_certificate" + a + ".pem");

            var params = {
                applicationUri:  "BAD SHOULD BE IN REQUEST",
                startDate: startDate,
                validity: validity
            };

            ca.signCertificateRequest(certificate_filename,self.certificate_request,params,function(err, certificate) {

                //xx console.log("Certificate = ",certificate);
                if (!err) {
                    fs.existsSync(certificate).should.eql(true);
                }
                //Serial Number: 4096 (0x1000)

                // should have 2 x -----BEGIN CERTIFICATE----- in the chain

                callback(err);
            });
        }
        async.series([

            function(callback) {
                // create a Certificate Signing Request
                createCertificateRequest(function(err,certificate_request) {
                    self.certificate_request = certificate_request;
                    callback(err)
                })
            },
            sign.bind(null,last_year,      200), // outdated
            sign.bind(null,last_year, 10 * 365), // valid
            sign.bind(null,next_year,      365)  // not started yet

        ],done);

    });

    it("T3 - should create various self-signed Certificates using the CA", function (done) {

        // using a CA to construct self-signed certificates provides the following benefits:
        //    - startDate can be easily specified in the past or the future
        //    - certificate can be revoked ??? to be checked.

        var privateKey = cm.privateKey;
        var certificate = path.join(test.tmpFolder,"sample_self_signed_certificate.pem");

        fs.existsSync(certificate).should.eql(false);
        ca.createSelfSignedCertificate(certificate,privateKey,{
            applicationUri: "SomeUri"
        },function(err) {
            fs.existsSync(certificate).should.eql(true);
            done(err);
        });
    });


    /**
     *
     * @param certificate  {String} certificate to create
     * @param privateKey
     * @param callback
     */
    function createSignedCertificate(certificate,privateKey,callback) {

        var startDate = new Date();
        var validity = 1000;
        var params = {
            applicationUri:  "BAD SHOULD BE IN REQUEST",
            startDate: startDate,
            validity: validity
        };
        ca.createSelfSignedCertificate(certificate,privateKey,params, function(err) {
            console.log("signed_certificate = signed_certificate",certificate);
            callback(err,certificate);
        });
    }
    it("T4 - should revoke a certificate",function(done) {

        var privateKey = cm.privateKey;
        var certificate = path.join(test.tmpFolder,"certificate_to_be_revoked1.pem");

        var tasks = [

            function(callback) {
                createSignedCertificate(certificate,privateKey,function(err) {
                    fs.existsSync(certificate).should.eql(true);
                    callback(err);
                });
            },

            function(callback) {
                ca.revokeCertificate(certificate,{},callback);
            }
        ];
        async.series(tasks,done);

    });


});
