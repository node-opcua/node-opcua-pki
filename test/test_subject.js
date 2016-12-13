
var should = require("should");
var Subject = require("../lib/misc/subject").Subject;


describe("Subject",function(){

    it("should compose a subject with common name only",function(){

        var subject  = new Subject({commonName: "Hello"});
        subject.toString().should.eql("/CN=Hello");

    });
    it("should compose a subject with a subject string",function(){

        var subject  = new Subject("/CN=Hello");
        subject.toString().should.eql("/CN=Hello");

    });


    it("should parse a SubjectLine ",function() {

        var str = "/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=Hello";

        var subject = Subject.parse(str);

        subject.commonName.should.eql("Hello");
    })
});