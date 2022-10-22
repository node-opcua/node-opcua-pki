import { should } from "should";
import { Subject } from "..";
describe("Subject", () => {

    it("should compose a subject with common name only", () => {
        const subject = new Subject({ commonName: "Hello" });
        subject.toStringForOPCUA().should.eql("CN=Hello");
        subject.toString().should.eql("/CN=Hello");
    });

    it("should compose a subject with a subject string - starting with a / (like in OpenSSL)", () => {
        const subject = new Subject("/CN=Hello");
        subject.toStringForOPCUA().should.eql("CN=Hello");
        subject.toString().should.eql("/CN=Hello");
    });
    
    it("should compose a subject with a subject string - correctly startign without a / (like in OPCUA-GDS)", () => {
        const subject = new Subject("CN=Hello");
        subject.toStringForOPCUA().should.eql("CN=Hello");
        subject.toString().should.eql("/CN=Hello");
    });

    it("should parse a SubjectLine ", () => {

        const str = "/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=Hello";
        const subject = Subject.parse(str);
        subject.commonName!.should.eql("Hello");
        subject.country!.should.eql("FR");
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
 
   
    it("should enclose data that contains special character  = with quote" , ()=>{
        const subject = new Subject({ commonName: "Hello=Hallo" });
        subject.toString().should.eql("/CN=\"Hello=Hallo\"");
    });
    it("should enclose data that contains special character / with quote" , ()=>{
        const subject = new Subject({ commonName: "Hello/Hallo" });
        subject.toString().should.eql("/CN=\"Hello/Hallo\"");
    });
    it("should replace unwanted quote character with a substitute character" , ()=>{
        const subject = new Subject({ commonName: 'Hello"Hallo"' });
        subject.commonName!.should.eql("Hello\"Hallo\"" );
        subject.toString().should.eql("/CN=Hello”Hallo”");
    });
    it("should parse a quoted string ", ()=>{
        const subject = new Subject("CN=Hello\'Hallo\'");
        subject.commonName!.should.eql("Hello\'Hallo\'" );
        subject.toString().should.eql("/CN=Hello'Hallo'");
    });
    it("should parse a quoted string ", ()=>{
        const subject = new Subject("CN=\"Hello/Hallo\"");
        subject.commonName!.should.eql("Hello/Hallo" );
        subject.toString().should.eql("/CN=\"Hello/Hallo\"");
    });
    
});
