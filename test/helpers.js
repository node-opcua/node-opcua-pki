/* global: module, it,describe, before */
require("requirish")._(module);
var toolbox = require("lib/pki/toolbox");
var path = require("path");

var tmpFolder = path.join(__dirname, "../tmp");

toolbox.g_config.silent = process.env.VERBOSE ? false :true;


module.exports.grep =
    function grep(data, regExp) {
        return data.split("\n").filter(function (l) {
            return l.match(regExp);
        }).join("\n");
    };


var doneOnce = false;
module.exports.beforeTest = function (self) {

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
