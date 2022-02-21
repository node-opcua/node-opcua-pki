import { should } from "should";

import { Subject } from "..";
describe("Subject", () => {

    it("should compose a subject with common name only", () => {
        const subject = new Subject({ commonName: "Hello" });
        subject.toString().should.eql("/CN=Hello");

    });

    it("should compose a subject with a subject string", () => {
        const subject = new Subject("/CN=Hello");
        subject.toString().should.eql("/CN=Hello");
    });

    it("should parse a SubjectLine ", () => {

        const str = "/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=Hello";
        const subject = Subject.parse(str);
        subject.commonName!.should.eql("Hello");
    });

    it("should parse a SubjectLine ", () => {

        const str = "/DC=MYDOMAIN/CN=Hello";

        const subject = Subject.parse(str);
        subject.commonName!.should.eql("Hello");
        subject.domainComponent!.should.eql("MYDOMAIN");
    });
    it("should parse a long CN with slashes SubjectLine ", () => {

        const str = "/CN=PC.DOMAIN.COM/path/scada/server@PC/DC=/O=Sterfive/L=Orleans/C=FR";

        const subject = Subject.parse(str);
        subject.commonName!.should.eql("PC.DOMAIN.COM/path/scada/server@PC");
        subject.domainComponent!.should.eql("");
    });
});
