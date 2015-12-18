require("requirish")._(module);

var pki = require("index");
var toolbox = pki.toolbox;

var path = require("path");
var fs = require("fs");
require("should");




function grep(data, regExp) {
    return data.split("\n").filter(function (l) {
        return l.match(regExp);
    }).join("\n");
}
describe("CertificateManager", function () {


    this.timeout(400000);

    require("./helpers")(this);
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

            console.log(params.startDate);

            cm.createSelfSignedCertificate(params, function (err) {

                if (err) {
                    return done(err);
                }

                var expected_certificate = path.join(options.location, "own/certs/self_signed_certificate.pem");
                fs.existsSync(expected_certificate).should.eql(true);

                toolbox.dumpCertificate(expected_certificate, function (err, data) {

                    fs.writeFileSync(path.join(self.tmpFolder, "dump_cert1.txt"),data);

                    console.log(data);

                    grep(data,/URI/).should.match(/URI:MY:APPLICATION:URI/);
                    grep(data,/DNS/).should.match(/DNS:localhost/);
                    grep(data,/DNS/).should.match(/DNS:my.domain.com/);

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
