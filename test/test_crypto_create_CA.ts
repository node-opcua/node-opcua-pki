// tslint:disable:no-console
import * as child_process from "child_process";
import * as fs from "fs";
import * as path from "path";
import {should} from "should";
import {dumpCertificate , ErrorCallback, Filename, make_path} from "..";
import {beforeTest, grep} from "./helpers";

const n = make_path;

function create_demo_certificates(cwd: Filename, callback: ErrorCallback) {
    call_crypto_create_CA("demo --dev", cwd, callback);
}

function call_crypto_create_CA(
    cmdArguments: string,
    cwd: Filename,
    callback: ErrorCallback
) {

    if (!fs.existsSync(cwd)) {
        return callback(new Error(" current folder shall exist " + cwd));
    }

    const rootFolder = process.cwd();
    const cmd = "node";
 
    const args1: string = n(path.join(rootFolder, "./bin/crypto_create_CA.js")) + " " + cmdArguments;
    const args = args1.replace("  ", " ").split(" ");

    const options = {
        cwd
    };

    const child = child_process.spawn(cmd, args, options);

    if (process.env.DEBUG) {
        console.log(" cwd = ", cwd);
        console.log(" cmd = ", cmd);
        console.log(" args = ", args);
        console.log("", cmd, args.join(" "));
    }

    child.stdout.on("data", () => {
        if (process.env.DEBUG) {
            process.stdout.write(".");
        }
    });

    const doLog = false;
    if (doLog) {
        const logFile = path.join(__dirname, "../tmp/log.txt");
        const logStream = fs.createWriteStream(logFile);
        child.stdout.pipe(logStream);
        child.stderr.pipe(logStream);
    }

    child.stderr.pipe(process.stderr);
    child.on("exit", (code: number) => {
        if (process.env.DEBUG) {
            console.log("done ... (" + code + ")");
        }
        callback();
    });
}

describe("testing test_crypto_create_CA", function(this: any) {

    this.timeout(2300000);

    const test = beforeTest(this);

    it("should create a PKI with demo certificates", (done: ErrorCallback) => {

        const cwd = path.join(__dirname, "../tmp");

        const certificate_file = path.join(cwd, "certificates/discoveryServer_cert_2048.pem");

        fs.existsSync(certificate_file).should.eql(false);

        console.log(" certificate_file = ", certificate_file);

        const date1 = new Date();

        create_demo_certificates(cwd, (err?: Error | null) => {

            if (err) { return done(err); }
            fs.existsSync(certificate_file).should.eql(true);

            // running a second time should be faster
            const date2 =  new Date();
            create_demo_certificates(cwd, (err?: Error | null) => {
                const date3 =  new Date();
                const initialTimeToConstructDemoCertificate = (date2.getTime() - date1.getTime());
                console.log(" t1 = ", initialTimeToConstructDemoCertificate);
                const timeToConstructDemoCertificateSecondTime = (date3.getTime() - date2.getTime());
                console.log(" t2 = ", timeToConstructDemoCertificateSecondTime);

                (initialTimeToConstructDemoCertificate / 5).should.be
                    .greaterThan(timeToConstructDemoCertificateSecondTime);

                done(err);
            });
        });
    });

    describe("self-signed certificates", () => {

        it("should create a self-signed certificate - variation 1", (done: ErrorCallback) => {
            const cwd = path.join(__dirname, "../tmp/zzz1");
            fs.mkdirSync(cwd);

            const csrFile = path.join(cwd, "my_certificate.pem.csr");
            const certificateFile = path.join(cwd, "my_certificate.pem");
            call_crypto_create_CA("certificate --selfSigned --silent=false", cwd, () => {

                fs.existsSync(certificateFile).should.eql(true,
                     "file " + certificateFile + " should exist");
                
                fs.existsSync(csrFile).should.eql(false, 
                    "useless signing request shall be automatically removed (" + csrFile + ")");
                done();
            });
        });

        it("should create a self-signed certificate - variation 2 - --output ", (done: ErrorCallback) => {
            const cwd = path.join(__dirname, "../tmp/zzz2");
            fs.mkdirSync(cwd);

            const expectedCertificate = path.join(cwd, "mycert.pem");
            call_crypto_create_CA(
                "certificate --selfSigned -o mycert.pem",
                cwd,
                () => {
                    fs.existsSync(expectedCertificate).should.eql(true);
                    fs.existsSync(path.join(cwd, "mycert.pem.csr"))
                        .should.eql(false, "useless signing request shall be automatically removed");

                    dumpCertificate(expectedCertificate, (err: Error | null, data?: string) => {

                        grep(data!, /Public.Key/).should.match(/Public.Key: \(2048 bit\)/);
                        // XX grep(data,/URI/).should.match(/URI:MY:APPLICATION:URI/);
                        // XX grep(data,/DNS/).should.match(/DNS:localhost/);
                        // XX grep(data,/DNS/).should.match(/DNS:my.domain.com/);
                        done();
                    });
                });

        });

        it("should create a self-signed certificate - variation 3 - --applicationUrI", (done: ErrorCallback) => {
            const cwd = path.join(__dirname, "../tmp/zzz3");
            fs.mkdirSync(cwd);

            const expectedCertificate = path.join(cwd, "mycert.pem");
            call_crypto_create_CA(
                "certificate -a urn:MYSERVER:APPLICATION --selfSigned -o mycert.pem",
                cwd,
                () => {

                    fs.existsSync(expectedCertificate).should.eql(true);

                    fs.existsSync(path.join(cwd, "mycert.pem.csr"))
                        .should.eql(false, "useless signing request shall be automatically removed");

                    dumpCertificate(expectedCertificate, (err: Error | null, data?: string) => {
                        grep(data!, /Public.Key/).should.match(/Public.Key: \(2048 bit\)/);
                        grep(data!, /URI/).should.match(/urn:MYSERVER:APPLICATION/);
                        // XX grep(data,/DNS/).should.match(/DNS:localhost/);
                        // XX grep(data,/DNS/).should.match(/DNS:my.domain.com/);
                        done();
                    });
                });

        });

        function daysBetween(date1: Date, date2: Date): number {
            // Get 1 day in milliseconds
            const oneDay = 1000 * 60 * 60 * 24;

            // Convert both dates to milliseconds
            const date1Ms = date1.getTime();
            const date2Ms = date2.getTime();

            // Calculate the difference in milliseconds
            const differenceMs = date2Ms - date1Ms;

            // Convert back to days and return
            return Math.round(differenceMs / oneDay);
        }

        it("should create a self-signed certificate - variation 4 - --validity", (done: ErrorCallback) => {

            const cwd = path.join(__dirname, "../tmp/zzz4");

            fs.mkdirSync(cwd);

            const expectedCertificate = path.join(cwd, "mycert.pem");
            const validity = 10; // days

            call_crypto_create_CA("certificate -v " + validity + " --selfSigned -o mycert.pem", cwd, () => {

                fs.existsSync(expectedCertificate).should.eql(true);
                fs.existsSync(path.join(cwd, "mycert.pem.csr"))
                    .should.eql(false, "useless signing request shall be automatically removed");

                dumpCertificate(expectedCertificate, (err: Error | null, data?: string) => {

                    grep(data!, /Public.Key/).should.match(/Public.Key: \(2048 bit\)/);
                    const _startDate = grep(data!, /Not Before/).match(/Not Before:(.*)/)![1].trim();
                    const _endDate = grep(data!, /Not After/).match(/Not After :(.*)/)![1].trim();
                    const startDate = new Date(Date.parse(_startDate));
                    const endDate = new Date(Date.parse(_endDate));

                    const validityCheck = daysBetween(startDate, endDate);

                    validityCheck.should.eql(validity);

                    done();
                });
            });
        });
        it("should create a self-signed certificate - variation 5 - --dns", (done: ErrorCallback) => {
            const cwd = path.join(__dirname, "../tmp/zzz5");
            fs.mkdirSync(cwd);

            const expectedCertificate = path.join(cwd, "mycert.pem");
            const validity = 10; // days

            call_crypto_create_CA("certificate -v " + validity + " --dns HOST1,HOST2 --selfSigned -o mycert.pem",
                cwd, () => {

                    fs.existsSync(expectedCertificate).should.eql(true);

                    dumpCertificate(expectedCertificate, (err: Error | null, data?: string) => {

                        grep(data!, /Public.Key/).should.match(/Public.Key: \(2048 bit\)/);
                        grep(data!, /DNS/).should.match(/DNS:HOST1/);
                        grep(data!, /DNS/).should.match(/DNS:HOST2/);

                        done();
                    });
                });
        });

        it("should create a self-signed certificate - variation 6 - --ip", (done: ErrorCallback) => {
            const cwd = path.join(__dirname, "../tmp/zzz6");
            fs.mkdirSync(cwd);

            const expectedCertificate = path.join(cwd, "mycert.pem");
            const validity = 10; // days

            call_crypto_create_CA("certificate -v " + validity +
                " --ip 128.12.13.13,128.128.128.128 --selfSigned -o mycert.pem",
                cwd, () => {

                    fs.existsSync(expectedCertificate).should.eql(true);

                    dumpCertificate(expectedCertificate, (err: Error | null, data?: string) => {

                        if (false) {
                            console.log(data);
                        }
                        grep(data!, /Public.Key/).should.match(/Public.Key: \(2048 bit\)/);
                        grep(data!, /IP/).should.match(/IP Address:128.12.13.13/);
                        grep(data!, /IP/).should.match(/IP Address:128.128.128.128/);

                        done();
                    });
                });
        });
    });

    describe("createCA & PKI", () => {
        it("@1 should create a CA and a PKI with 4096 bits keys", (done: ErrorCallback) => {

            const cwd = path.join(__dirname, "../tmp/tmp4096");
            fs.mkdirSync(cwd);
            call_crypto_create_CA("createCA --keySize 4096", cwd, () => {

                const caPrivateKey = path.join(__dirname,
                    "../tmp/tmp4096/certificates/CA/private/cakey.pem");
                fs.existsSync(caPrivateKey).should.eql(true);
                call_crypto_create_CA("createPKI --keySize 4096", cwd, () => {
                    const pkiPrivateKey = path.join(__dirname,
                        "../tmp/tmp4096/certificates/PKI/own/private/private_key.pem");
                    fs.existsSync(pkiPrivateKey).should.eql(true);

                    done();
                });
            });
        });
    });

    describe("certificates signed by Local CA Authority", () => {

        it("should create a signed certificate - variation 1", (done: ErrorCallback) => {
            const cwd = path.join(__dirname, "../tmp/yyy1");
            fs.mkdirSync(cwd);
            call_crypto_create_CA("certificate", cwd, () => {
                done();
            });
        });

        xit("ZZ0 should create a signed certificate - variation 2", (done: ErrorCallback) => {

            const cwd = path.join(__dirname, "../tmp/yyy2");
            fs.mkdirSync(cwd);

            const expectedCertificate = path.join(cwd, "mycert.pem");

            call_crypto_create_CA("certificate -o " + "mycert.pem", cwd, () => {

                fs.existsSync(expectedCertificate).should.eql(true);
                done();
            });
        });
    });
});
