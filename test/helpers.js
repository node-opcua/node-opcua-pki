/* global: module, it,describe, before */

var toolbox = require("../lib/pki/toolbox");
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
module.exports.beforeTest = function (self,optional_function) {

    self.timeout("2 minutes");

    before(function (done) {

        function __done() {
            doneOnce = true;
            if (optional_function) {
                optional_function(done);
            } else {
                done();
            }
        }

        self.tmpFolder = tmpFolder;
        if (doneOnce) {
            return __done();
        }
        var del = require("del");
        del(tmpFolder).then(function () {
            toolbox.mkdir(tmpFolder);
            __done();
        });
    });

};
