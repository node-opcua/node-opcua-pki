Error.stackTraceLimit = Infinity;
require("requirish")._(module);
var pki = require("index");

var crypto_utils = require("node-opcua-crypto").crypto_utils;


var path = require("path");
var async = require("async");
var fs = require("fs");

var should = require("should");


// ------------------------------------------------- some useful dates
function get_offset_date(date, nb_days) {
    var d = new Date(date.getTime());
    d.setDate(d.getDate() + nb_days);
    return d;
}

var today = new Date();
var lastYear = get_offset_date(today, -365);
var nextYear = get_offset_date(today,  365);
var yesterday = get_offset_date(today, -1);


describe("test certificate validation",function() {

    var test = this;

    var certificateManager ;
    var certificateAuthority;

    /**
     * @method createCertificate
     * @param params
     * @param params.applicationUri {String}
     * @param params.dns            {String[]}
     * @param callback
     */
    function createCertificate(certificate,params,callback) {

        var the_certificate_request;
        async.series([

            function(callback) {
                // lets create
                certificateManager.createCertificateRequest(params,function(err,csr_file){
                    if(err) { return callback(err); }
                    the_certificate_request = csr_file;
                    //xx console.log("csr_file               = ",the_certificate_request);
                    callback();
                });
            },
            function(callback) {

                //xx console.log("the_certificate_request= ",the_certificate_request);
                //xx console.log("certificate            = ",certificate);
                fs.existsSync(certificate).should.eql(false);
                fs.existsSync(the_certificate_request).should.eql(true);
                certificateAuthority.signCertificateRequest(certificate,the_certificate_request,params,function(err){
                    fs.existsSync(the_certificate_request).should.eql(true);
                    fs.existsSync(certificate).should.eql(true);
                    callback(err);
                })
            }
        ],callback);
    }

    var certificate_out_of_date;
    var certificate_not_yet_active;
    var certificate_valid;
    var certificate_valid_untrusted;

    function prepare_test(done){


        var optionsCA = {location: path.join(test.tmpFolder, "TEST_CA")};
        certificateAuthority = new pki.CertificateAuthority(optionsCA);

        var optionsPKI = {location: path.join(test.tmpFolder, "TEST_PKI")};
        certificateManager = new pki.CertificateManager(optionsPKI);

        async.series([

            function (callback) {
                certificateAuthority.initialize(callback);
            },
            function (callback) {
                certificateManager.initialize(callback);
            },
            function (callback) {
                certificate_out_of_date = path.join(test.tmpFolder, "certificate_out_of_date.pem");
                createCertificate(certificate_out_of_date,{applicationUri: "SOMEURI", startDate: lastYear, duration: 300 },callback)
            },
            function (callback) {
                certificate_not_yet_active = path.join(test.tmpFolder, "certificate_notyetactive.pem");
                createCertificate(certificate_not_yet_active,{applicationUri: "SOMEURI", startDate: nextYear, duration: 10000 },callback)
            },
            function (callback) {
                certificate_valid = path.join(test.tmpFolder, "certificate_valid.pem");
                createCertificate(certificate_valid,{applicationUri: "SOMEURI", startDate: yesterday, duration: 10 },callback)
            },
            function (callback) {
                certificate_valid_untrusted = path.join(test.tmpFolder, "certificate_valid_untrusted.pem");
                createCertificate(certificate_valid_untrusted,{applicationUri: "SOMEURI", startDate: yesterday, duration: 10 },callback)
            }
        ],done);
    }

    require("./helpers").beforeTest(this,prepare_test);

    describe("should verify ",function(){


        var localCertificateManager;

        var cert1 ,cert2, cert3 ,certificate_valid_untrusted_A;
        before(function(done) {
            var optionsPKI2 = {location: path.join(test.tmpFolder, "TEST_PKI2")};
            localCertificateManager = new pki.CertificateManager(optionsPKI2);
            // get certificate

            cert1 = crypto_utils.readCertificate(certificate_out_of_date);
            cert2 = crypto_utils.readCertificate(certificate_not_yet_active);
            cert3 = crypto_utils.readCertificate(certificate_valid);
            certificate_valid_untrusted_A = crypto_utils.readCertificate(certificate_valid_untrusted);


            async.series([
                function (callback) {
                    localCertificateManager.trustCertificate(cert3,callback);
                },
                function (callback) {
                    localCertificateManager.rejectCertificate(certificate_valid_untrusted_A,callback);
                }
            ],done)
        });

        it("should detect null certificate",function(done) {
            localCertificateManager.verifyCertificate(null, function (err, status) {
                err.message.should.match("BadSecurityChecksFailed");
                done();
            });
        });

        it("should detect out of date certificate",function(done) {
            localCertificateManager.verifyCertificate(cert1, function (err, status) {
                err.message.should.match("BadCertificateTimeInvalid");
                done();
            });
        });
        it("should detect 'not active yet' certificate",function(done) {
            localCertificateManager.verifyCertificate(cert2, function (err, status) {
                err.message.should.match("BadCertificateTimeInvalid");
                done();
            });
        });

        it("should detect a valid certificate",function(done) {
            localCertificateManager.verifyCertificate(cert3, function (err, status) {
                should(err).eql(null);//.message.should.match("BadCertificateTimeInvalid");
                done();
            });
        });

        it("should detect untrusted certificate",function(done) {
            localCertificateManager.verifyCertificate(certificate_valid_untrusted_A, function (err, status) {
                err.message.should.match("BadCertificateUntrusted");
                done();
            });
        });


    });
});