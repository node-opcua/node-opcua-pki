require("requirish")._(module);

var pki = require("index");
var toolbox = pki.toolbox;

var path = require("path");
var fs = require("fs");
require("should");


var grep = require("./helpers").grep;

describe("toolbox",function(){

    this.timeout(400000);

    require("./helpers").beforeTest(this);


    var tmpFolder = path.join(__dirname,"../tmp");
    var private_key = path.join(tmpFolder,"some_private_key");

    before(function(done) {
        toolbox.mkdir(tmpFolder);
        toolbox.createPrivateKey(private_key,2048,function() {
            fs.existsSync(private_key).should.eql(true);
            done();
        });
    });

    it("should getPublicKeyFromPrivateKey",function(done) {

        var public_key = path.join(tmpFolder,"some_public_key");
        toolbox.getPublicKeyFromPrivateKey(private_key,public_key,function(err){
            fs.existsSync(public_key).should.eql(true);

            var data  = fs.readFileSync(public_key,"ascii");

            data.should.match(/-----BEGIN PUBLIC KEY-----/);
            data.should.match(/-----END PUBLIC KEY-----/);

            done(err);
        });

    });

    it("should getPublicKeyFromCertificate",function(done) {

        var sample_certificate = path.join(__dirname,"fixtures/sample_self_signed_certificate.pem");
        var public_key = path.join(tmpFolder,"some_public_key2");

        toolbox.getPublicKeyFromCertificate(sample_certificate,public_key,function(err){
            fs.existsSync(public_key).should.eql(true);

            var data  = fs.readFileSync(public_key,"ascii");
            data.should.match(/-----BEGIN PUBLIC KEY-----/);
            data.should.match(/-----END PUBLIC KEY-----/);

            data.should.match(/-----BEGIN CERTIFICATE-----/);
            data.should.match(/-----END CERTIFICATE-----/);

            done(err);
        });

    });

});