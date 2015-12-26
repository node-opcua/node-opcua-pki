require("requirish")._(module);

Error.stackTraceLimit = Infinity;

var pki = require("index");
var toolbox = pki.toolbox;

var path = require("path");
var fs = require("fs");
var should = require("should");
var assert = require("assert");
var _ = require("underscore");

var grep = require("./helpers").grep;
var async = require("async");

describe("CertificateManager", function () {


    this.timeout(400000);

    require("./helpers").beforeTest(this);
    var self;
    before(function () {
        self = this;
    });

    it("should create a certificateManager", function (done) {

        var options = {
            location: path.join(self.tmpFolder, "PKI")
        };

        var cm = new pki.CertificateManager(options);

        cm.initialize(function (err) {

            fs.existsSync(path.join(options.location)).should.eql(true);
            fs.existsSync(path.join(options.location, "trusted")).should.eql(true);
            fs.existsSync(path.join(options.location, "rejected")).should.eql(true);
            fs.existsSync(path.join(options.location, "own")).should.eql(true);
            fs.existsSync(path.join(options.location, "own/certs")).should.eql(true);
            fs.existsSync(path.join(options.location, "own/private")).should.eql(true);

            fs.existsSync(path.join(options.location, "own/private/private_key.pem")).should.eql(true);

            done(err);
        });
    });

    it("should create its own self-signed certificate", function (done) {

        var options = {
            location: path.join(this.tmpFolder, "PKI1")
        };

        var cm = new pki.CertificateManager(options);
        cm.initialize(function (err) {

            var params = {
                applicationUri: "MY:APPLICATION:URI",
                // can only be TODAY due to openssl limitation : startDate: new Date(2010,2,2),
                duration: 365 * 7,
                dns: [
                    "localhost",
                    "my.domain.com"
                ],
                ip: [
                   "192.123.145.121"
                ]
            };
            if (err) {
                return done(err);
            }

            //xx console.log(params.startDate);

            cm.createSelfSignedCertificate(params, function (err) {

                if (err) {
                    return done(err);
                }

                var expected_certificate = path.join(options.location, "own/certs/self_signed_certificate.pem");
                fs.existsSync(expected_certificate).should.eql(true);

                toolbox.dumpCertificate(expected_certificate, function (err, data) {

                    fs.writeFileSync(path.join(self.tmpFolder, "dump_cert1.txt"),data);

                    //console.log(data);

                    grep(data,/URI/).should.match(/URI:MY:APPLICATION:URI/);
                    grep(data,/DNS/).should.match(/DNS:localhost/);
                    grep(data,/DNS/).should.match(/DNS:my.domain.com/);


                    if (toolbox.openssl_version.match(/1.0.2/)) {
                        // note openssl version 1.0.1 does support sha256 signature
                        grep(data, /Signature Algorithm/).should.match(/Signature Algorithm: sha256WithRSAEncryption/);
                    }
                    grep(data, /SelfSigned/).should.match(/SelfSigned/);

                    var y = (new Date()).getFullYear();
                    grep(data, /Not Before/).should.match(new RegExp(y.toString() + " GMT"));
                    grep(data, /Not After/).should.match(new RegExp((y + 7).toString() + " GMT"));

                    done();
                });

            });
        });
    });

});

var crypto_utils = require("node-opcua-crypto").crypto;


describe("CertificateManager managing certificate", function () {

    this.timeout(400000);

    require("./helpers").beforeTest(this);
    var self;
    var cm;

    function createSampleCertificateDer(certificate,callback) {

        assert(_.isFunction(callback));

        certificate = toolbox.make_path(certificate);
        // openssl req -x509 -days 365 -nodes -newkey rsa:1024 -keyout private_key.pem -outform der -out certificate.der"
        toolbox.execute_openssl("req -x509 -days 365 -nodes -newkey rsa:1024 " +
            "-batch -keyout private_key.pem " +
            "-outform der -out " + certificate,{},function(err){
            assert(fs.existsSync(certificate));

            callback(err);
        });
    }

    var sample_certificate1_der = path.join(__dirname,"fixtures/sample_certifcate1.der");
    var sample_certificate2_der = path.join(__dirname,"fixtures/sample_certifcate2.der");
    var sample_certificate3_der = path.join(__dirname,"fixtures/sample_certifcate3.der");
    var sample_certificate4_der = path.join(__dirname,"fixtures/sample_certifcate4.der");
    var sample_certificate5_der = path.join(__dirname,"fixtures/sample_certifcate5.der");

    before(function (done) {
        self = this;
        var options = {
            location: path.join(this.tmpFolder, "PKI2")
        };
        cm = new pki.CertificateManager(options);

        async.series([
            createSampleCertificateDer.bind(null,sample_certificate1_der),
            createSampleCertificateDer.bind(null,sample_certificate2_der),
            createSampleCertificateDer.bind(null,sample_certificate3_der),
            createSampleCertificateDer.bind(null,sample_certificate4_der),
        ],done);
    });
    it("CertificateManager#_getCertificateStatus should return 'unknown' if the certificate is first seen",function(done) {

//xx        var certificate = crypto_utils.readCertificate(sample_certificate_der);
        var certificate = fs.readFileSync(sample_certificate1_der);
        assert(certificate instanceof Buffer);

        async.series([

            function(callback) {
                toolbox.execute_openssl("x509 -inform der -in " + sample_certificate1_der + " " +
                    "-fingerprint -noout ",{},function(err){
                    callback(err);
                });
            },
            function (callback) {
                cm._getCertificateStatus(certificate,function(err,status){
                    status.should.eql("unknown");
                    callback();
                });
            }
        ],done)

    });

    it("CertificateManager#getCertificateStatus should store unknown certificate into the untrusted folder",function(done) {

        var certificate = fs.readFileSync(sample_certificate2_der);
        assert(certificate instanceof Buffer);

        async.series([
            function(callback) {
                cm.getCertificateStatus(certificate, function (err, status) {
                    status.should.eql("rejected");
                    callback();
                });
            },
            function(callback) {
                cm._getCertificateStatus(certificate, function (err, status) {
                    status.should.eql("rejected");
                    callback();
                });
            }
        ],done)

    });
    it("CertificateManager#trustCertificate  should store in trusted folder",function(done) {

        var certificate = fs.readFileSync(sample_certificate3_der);
        assert(certificate instanceof Buffer);

        async.series([
            function(callback) {
                cm.getCertificateStatus(certificate, function (err, status) {
                    status.should.eql("rejected");
                    callback();
                });
            },
            function(callback) {
                cm._getCertificateStatus(certificate, function (err, status) {
                    status.should.eql("rejected");
                    callback();
                });
            },
            function(callback) {
                cm.trustCertificate(certificate, function (err) {
                    should(err).eql(null);
                    callback();
                });
            },
            function(callback) {
                cm._getCertificateStatus(certificate, function (err, status) {
                    status.should.eql("trusted");
                    callback();
                });
            },
            function(callback) {
                cm.rejectCertificate(certificate, function (err) {
                    should(err).eql(null);
                    callback();
                });
            },
            function(callback) {
                cm._getCertificateStatus(certificate, function (err, status) {
                    status.should.eql("rejected");
                    callback();
                });
            },
            function(callback) {
                cm.trustCertificate(certificate, function (err) {
                    should(err).eql(null);
                    callback();
                });
            }


        ],done)

    });

});
