import * as path from "path";
import * as fs from "fs";
import { promisify, isRegExp } from "util";
import * as sinon from "sinon";
import * as dir from "node-dir";
import *  as chalk from "chalk";
import * as should from "should";

import {
    readCertificate, Certificate, split_der, makeSHA1Thumbprint
} from "node-opcua-crypto";
import { beforeTest } from "./helpers";
import { CertificateManager, CertificateManagerOptions, VerificationStatus } from "..";

async function copyFiles(sourceFolder: string, destinationFolder: string) {


    const files: string[] = await (promisify(dir.files)(sourceFolder) as Promise<string[]>);

    for (const file of files) {
        const inputFilename = file;
        const baseName = path.basename(file);
        const outputFilename = path.join(destinationFolder, baseName);
        await new Promise(resolve => {
            fs.readFile(inputFilename, (err, data: Buffer) => {
                if (err) {
                    // tslint:disable-next-line: no-console
                    console.log(inputFilename);
                    resolve();
                    return;
                }
                fs.writeFile(outputFilename, data, () => {
                    resolve();
                });
            });
        });
    }
}
const copyFilesAsync = copyFiles;;

async function getCertificateList(): Promise<string[]> {

    const sourceFolder = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs");

    const files: string[] = await (promisify(dir.files)(sourceFolder) as Promise<string[]>);
    return files;
}
enum RSAFLAG {
    "UNKNOWN",
    "Sha1_1024",
    "Sha1_2048",
    "Sha256_2048",
    "Sha256_4096"
}
enum TimeValidity {
    expired,
    not_yet_valid,
    ok
}
interface CertFlags {
    trusted?: boolean;
    validity: TimeValidity;
    manipulated: boolean;
    wrongCert?: boolean;
    revoked: boolean;
}

interface CAFlags {
    trusted?: boolean;
    //    validity?: TimeValidity;
    revocationListUnknown?: boolean;
    isIssuer?: boolean;
}
interface Status {
    ca1?: CAFlags,
    ca2?: CAFlags,
    certFlags: CertFlags,
    rsaFlag: RSAFLAG;
}
function getFlags(filename: string): Status {


    const basename = path.basename(filename);
    const n = basename.replace(/ctt_.*app|ctt_.*usr|Sha1_1024|Sha1_2048|Sha256_2048|Sha256_4096|incorrect|ip|uri/g, "");

    const m = basename.match(/(Sha1_1024|Sha1_2048|Sha256_2048|Sha256_4096)/)
    const rsa = !m ? "" : m[1];
    const rsaFlag = (RSAFLAG as any)[rsa] || RSAFLAG.UNKNOWN;

    const certFlags: CertFlags = {
        trusted: !!n.match("T") ? true : (n.match("U") ? false : undefined),
        validity: n.match("E") ? TimeValidity.expired : (n.match("V") ? TimeValidity.not_yet_valid : TimeValidity.ok),
        manipulated: !!n.match("S") && !!filename.match("incorrect"),
        wrongCert: !!n.match("S") && !filename.match("incorrect"),
        revoked: !!n.match("R")
    }
    function extractCAflags(pattern: string): CAFlags | undefined {
        const ca1str = basename.match(pattern + "([IUTC]+)");
        if (!ca1str) {
            return undefined;
        }
        const c = ca1str[1];
        return {
            trusted: c.match("T") ? true : (c.match("U") ? false : undefined),
            revocationListUnknown: c.match("C") ? true : false,
            isIssuer: c.match("I") ? true : false,
        }
    }
    const ca1 = extractCAflags("_ca1");
    const ca2 = extractCAflags("_ca2");
    return { certFlags, rsaFlag, ca1, ca2 };

}

const pad = "---";
const pa0 = "   ";
function flagsHeader() {
    const str1: string[] = [];
    str1.push("Root CA -------" + pad + "----------------------+"); //
    str1.push("Sub CA1 -------" + pad + "-----------------+    |"); // 🟢👍⛔🟢
    str1.push("Manipulated----" + pad + "------------+    |    |"); // 🗱😈
    str1.push("Revoked -------" + pad + "---------+  |    |    |"); // ⌛⏰🔜
    str1.push("Validity-------" + pad + "------+  |  |    |    |"); // ⌛⏰🔜
    str1.push("Trusted--------" + pad + "---+  |  |  |    |    |"); // ? | U | T
    str1.push("               " + pa0 + "   v  v  v  v |  v  | v "); // 👍⛔🟢

    const p = " ".padEnd(11) + " ";
    return str1.map(a => p + a).join("\n");
}

function caFlag(c?: CAFlags): string {
    let str = "   ";
    if (!c) {
        return str;
    }
    const i = c.isIssuer ? chalk.yellow("I") : " ";
    const t = c.trusted === undefined ? " " : (c.trusted ? chalk.green("T") : chalk.red("U"));
    const r = c.revocationListUnknown ? chalk.magenta("C") : " ";

    str = `${i}${t}${r}`;
    return str;
}
function flagsToString(s: Status) {
    const t = s.certFlags.trusted ? chalk.green("T") : chalk.red("U");
    const v = s.certFlags.validity === TimeValidity.expired ? chalk.red("E") : (s.certFlags.validity === TimeValidity.not_yet_valid ? chalk.redBright("V") : chalk.green("√"));
    const r = s.certFlags.revoked ? chalk.magenta("R") : " ";
    const m = s.certFlags.manipulated ? chalk.red("$") : (s.certFlags.wrongCert ? chalk.cyan("w") : " ");

    const ca1 = caFlag(s.ca1);
    const ca2 = caFlag(s.ca2);
    const x = "  " + pa0 + `   ${t}  ${v}  ${r}  ${m} | ${ca1} | ${ca2} `; // 👍⛔🟢
    return x;
}
/**
 * ctt = application instance certificate for the usage by the CTT.
 * ca1 = certificate authority of level 1 in the chain. Also called root ca.
 * caX = certificate authority of level X in the chain. E.g. 2 for secondary ca.
 * usr = user certificate which are used for X509 IdentityToken tests.
 * T = trusted by being placed in the trusted folder of the server.
 * U = untrusted by not being known to the server
 * I = issuers by being available in the issuers folder of the server
 * C = revocation list unavailable which means the according revocation list is not available to the server
 * E = expired which means the validation time of the certificate has been exceeded
 * V = validity which means the certificate is not yet valid.
 * S = manipulated information ...
 * incorrect = incorrect signature by alterning bytes in the signature itself.
 * ip = incorrect ip.
 * sha1_1024 = certificate signed with the Sha1 algorithm and a key length of 1024 bit.
 * sha1_2048 = certificate signed with the Sha1 algorithm and a key length of 2048 bit.
 * sha256_2048 = certificate signed with the Sha256 algorithm and a key length of 2048 bit.
 * sha256_4096 = certificate signed with the Sha1 algorithm and a key length of 4096 bit.
 */


describe("testing CTT Certificate use cases", function (this: Mocha.Suite) {

    this.timeout(2300000);

    const testData = beforeTest(this);

    let clock: sinon.SinonFakeTimers;
    beforeEach(() => {
        clock = sinon.useFakeTimers(new Date(2020, 4, 11));
    });
    afterEach(() => {
        clock.restore();
    });
    before(async () => {

        fs.mkdirSync(path.join(testData.tmpFolder, "ctt"));
        const applicationPKI = new CertificateManager({
            location: path.join(testData.tmpFolder, "ctt/applicationPKI")
        });
        await applicationPKI.initialize();

        const x509userIdentityPKI = new CertificateManager({
            location: path.join(testData.tmpFolder, "ctt/userIdentityPKI")
        });
        await x509userIdentityPKI.initialize();

        // tslint:disable-next-line: no-console
        console.log("Copying files")
        const promises: Promise<void>[] = [];

        const rootApp = path.join(__dirname, "fixtures/CTT_sample_certificates/copyToServer/ApplicationInstance_PKI");
        const rootUI = path.join(__dirname, "fixtures/CTT_sample_certificates/copyToServer/X509UserIdentity_PKI");

        promises.push(copyFilesAsync(path.join(rootApp, "issuers/certs"), applicationPKI.issuersCertFolder));
        promises.push(copyFilesAsync(path.join(rootApp, "issuers/crl"), applicationPKI.issuersCrlFolder));
        promises.push(copyFilesAsync(path.join(rootApp, "trusted/certs"), applicationPKI.trustedFolder));
        promises.push(copyFilesAsync(path.join(rootApp, "trusted/crl"), applicationPKI.crlFolder));

        promises.push(copyFilesAsync(path.join(rootUI, "issuers/certs"), x509userIdentityPKI.issuersCertFolder));
        promises.push(copyFilesAsync(path.join(rootUI, "issuers/crl"), x509userIdentityPKI.issuersCrlFolder));
        promises.push(copyFilesAsync(path.join(rootUI, "trusted/certs"), x509userIdentityPKI.trustedFolder));
        promises.push(copyFilesAsync(path.join(rootUI, "trusted/crl"), x509userIdentityPKI.crlFolder));

        await Promise.all(promises);
    });
    async function test_verify(
        certFilename: string,
        certificateManager: CertificateManager
    ) {

        const certificate = readCertificate(certFilename);

        const nbInChain = split_der(certificate).length;
        const status = await certificateManager.verifyCertificate(certificate);
        const flags = getFlags(certFilename);

        // tslint:disable-next-line: no-console
        console.log(path.basename(certFilename).padEnd(24), flagsToString(flags), status.toString().padEnd(37), nbInChain, makeSHA1Thumbprint(certificate).toString("hex").substr(0, 10));
        if (flags.certFlags.validity === TimeValidity.expired || flags.certFlags.validity === TimeValidity.not_yet_valid) {
            status.should.eql(VerificationStatus.BadCertificateTimeInvalid);
        }
        if (flags.ca2 && flags.ca2.trusted === false) {
            status.should.eql("BadSecurityChecksFailed"); // Issuer not known
        }
        if (!flags.certFlags.trusted && flags.certFlags.validity === TimeValidity.ok && !flags.ca1 && !flags.ca2) {
            status.should.eql("BadCertificateUntrusted");
        }
    }

    it("XGXG should", async () => {

        const applicationPKI = new CertificateManager({
            location: path.join(testData.tmpFolder, "ctt/applicationPKI")
        });
        await applicationPKI.initialize();

        const list = await getCertificateList();
        const applicationCertificates = list.filter((f) => path.basename(f).match(/^ctt_.*app/));

        const file1 = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I_ca2T_appU.der");
        await test_verify(file1, applicationPKI);

        // tslint:disable-next-line: no-console
        console.log(flagsHeader());
        for (const certFilename of applicationCertificates) {
            await test_verify(certFilename, applicationPKI);
        }
    });
    it("XGXG2 should ", async () => {
        const x509YuserIdentiyPKI = new CertificateManager({
            location: path.join(testData.tmpFolder, "ctt/userIdentityPKI")
        });
        await x509YuserIdentiyPKI.initialize();
        const list = await getCertificateList();
        const applicationCertificates = list.filter((f) => path.basename(f).match(/^ctt_.*usr/));

        // tslint:disable-next-line: no-console
        console.log(flagsHeader());
        for (const certFilename of applicationCertificates) {
            await test_verify(certFilename, x509YuserIdentiyPKI);
        }
    });
    it("XGXG3 should check for revoked certificates", async () => {

        // ctt_ca1I_ca2T_usrTR.der
        const applicationPKI = new CertificateManager({
            location: path.join(testData.tmpFolder, "ctt/applicationPKI")
        });
        await applicationPKI.initialize();

        const file1 = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I_ca2T_appU.der");
        const file2R = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I_ca2T_usrTR.der");

        const cert1 = await readCertificate(file1);
        (await applicationPKI.isCertificateRevoked(cert1)).should.eql("BadCertificateRevocationUnknown");

        const cert2R = await readCertificate(file2R);
        const isRevoked2 = await applicationPKI.isCertificateRevoked(cert2R);
        isRevoked2.should.eql(VerificationStatus.BadCertificateRevocationUnknown);
    });

    it("XGXG4 debug2", async () => {
        const applicationPKI = new CertificateManager({
            location: path.join(testData.tmpFolder, "ctt/applicationPKI")
        });
        await applicationPKI.initialize();

        const file1 = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1TC_ca2I_appT.der");

        const certificate = await readCertificate(file1);
        (await applicationPKI.isCertificateRevoked(certificate)).should.eql("BadCertificateRevocationUnknown");
        const status = await applicationPKI.verifyCertificate(certificate);
        status.should.eql(VerificationStatus.BadCertificateIssuerRevocationUnknown);

        console.log(status);


    })
});
