require("requirish")._(module);

var pki = require("lib/pki/certificate_manager");
var path = require("path");
var fs = require("fs");
require("should");

var toolbox = require("lib/pki/certificate_toolbox");

//xx toolbox.g_config.silent = true;

function grep(data, regExp) {
    return data.split("\n").filter(function (l) {
        return l.match(regExp);
    }).join("\n");
}
describe("CertificateManager", function () {


    this.timeout(400000);

    require("./helpers")();

    it("should create a certificateManager", function (done) {

        var options = {
            location: path.join(this.tmpFolder, "PKI")
        };

        if (0) {
            removeFolder(options.location);
            fs.existsSync(path.join(options.location)).should.eql(false);
            fs.existsSync(path.join(options.location, "trusted")).should.eql(false);
            fs.existsSync(path.join(options.location, "rejected")).should.eql(false);
            fs.existsSync(path.join(options.location, "own")).should.eql(false);
            fs.existsSync(path.join(options.location, "own/certs")).should.eql(false);
            fs.existsSync(path.join(options.location, "own/private")).should.eql(false);
        }


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
                applicationUri: "TOTO",
                // can only be TODAY due to openssl limitation : startDate: new Date(2010,2,2),
                duration: 365 * 7
            };
            if (err) {
                return done(err);
            }

            console.log(params.startDate);

            cm.createSelfSignedCertificate(params, function (err) {

                if (err) {
                    return done(err);
                }

                var expected_certificate = path.join(options.location, "own/certs/self_signed_certificate.pem");
                fs.existsSync(expected_certificate).should.eql(true);

                toolbox.dumpCertificate(expected_certificate, function (err, data) {

                    console.log(data);

                    grep(data, /Signature Algorithm/).should.match(/Signature Algorithm: sha256WithRSAEncryption/);
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
