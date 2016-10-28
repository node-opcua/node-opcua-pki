"use strict";
var async = require("async");
var path = require("path");
var child_process = require("child_process");
var fs = require("fs");
var should = require("should");


var pki = require("../index");
var toolbox = pki.toolbox;
var q = toolbox.quote;
var n = toolbox.make_path;

function create_demo_certificates(callback) {

    var cmd = "node " + q(n(path.join(__dirname,"../bin/crypto_create_CA.js"))) + " demo  --dev";

    var options = {
        cwd: path.join(__dirname,"../tmp")
    };

    var the_code = 61;
    var child = child_process.exec(cmd,options,function(err) {
    });

    //xx console.log(" cmd = ",cmd);
    //xx child.stdout.pipe(process.stdout);

    child.on('close', function(code) {
        the_code = code;
        console.log("done ... (" + the_code + ")");
        callback();
    });
}

describe("testing test_crypto_create_CA",function() {

    require("./helpers").beforeTest(this);

    it("should create a PKI",function(done){

        fs.existsSync(
          path.join(__dirname,"../tmp/certificates/discoveryServer_cert_2048.pem"))
          .should.eql(false);

        create_demo_certificates(function(err){
            fs.existsSync(
              path.join(__dirname,"../tmp/certificates/discoveryServer_cert_2048.pem"))
              .should.eql(true);
            done(err);
        });
    });
});
