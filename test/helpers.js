/* global: it,describe, before */
require("requirish")._(module);
var toolbox = require("lib/pki/certificate_toolbox");
var path = require("path");

var tmpFolder = path.join(__dirname, "../tmp");

toolbox.g_config.silent = process.env.VERBOSE ? false :true;

var doneOnce = false;
module.exports = function (self) {

    before(function (done) {

        self.timeout(400000);

        this.tmpFolder = tmpFolder;
        if (doneOnce) {
            return done();
        }
        var del = require("del");
        del(tmpFolder).then(function () {
            toolbox.mkdir(tmpFolder);
            doneOnce = true;
            done();
        });
    });

};
