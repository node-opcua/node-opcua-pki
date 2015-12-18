/* global: it,describe */
require("requirish")._(module);

var path = require("path");
//xx var fs = require("fs");
//xx var should = require("should");

var toolbox = require("lib/pki/certificate_toolbox");

var CertificateAuthority = require("lib/pki/certificate_authority").CertificateAuthority;

describe("Certificate Authority", function () {

    this.timeout(400000);

    require("./helpers")();

    it("should read openssl version", function (done) {

        toolbox.execute_openssl("version", {cwd: "."}, function (err) {
            done(err);
        });
    });

    it("should create a CertificateAuthority", function (done) {

        var options = {
            location: path.join(this.tmpFolder, "CA")
        };

        var ca = new CertificateAuthority(options);

        ca.initialize(function (err) {
            done(err);
        });
    });
});
