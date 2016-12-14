
var install_prerequisite = require("../lib/misc/install_prerequisite").install_prerequisite;
describe("testing install_prerequisite",function() {


    it("should verify prerequisite",function(done){

        install_prerequisite(function(err){

            done(err);
        });
    });

});
