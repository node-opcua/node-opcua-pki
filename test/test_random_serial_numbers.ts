import path from "node:path";
import { exploreCertificate, readCertificateChain } from "node-opcua-crypto";
import { CertificateAuthority } from "node-opcua-pki";
import should from "should";
import { makeLeafCsr } from "./_ca_backends";
import { beforeTest } from "./helpers";

/**
 * Serial numbers used to be a counter starting at 1000: predictable, and a CA
 * re-created under the same name handed out 1000, 1001, ... again, so two of
 * its certificates could share a serial (and a CRL entry). They are now 16
 * random bytes, as the CA/Browser Forum baseline asks (at least 64 bits).
 */
describe("random certificate serial numbers", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    const serialOf = (file: string) =>
        exploreCertificate(readCertificateChain(file)[0]).tbsCertificate.serialNumber.replace(/:/g, "").toUpperCase();

    async function issue(ca: CertificateAuthority, folder: string, count: number): Promise<{ serials: string[]; files: string[] }> {
        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, folder), { applicationUri: `urn:test:${folder}` });
        const serials: string[] = [];
        const files: string[] = [];
        for (let i = 0; i < count; i++) {
            const out = path.join(cm.rootDir, `own/certs/signed_${i}.pem`);
            await ca.signCertificateRequest(out, csr, {
                applicationUri: `urn:test:${folder}`,
                startDate: new Date(),
                validity: 30
            });
            serials.push(serialOf(out));
            files.push(out);
        }
        await cm.dispose();
        return { serials, files };
    }

    for (const backend of ["openssl", "native"] as const) {
        it(`${backend}: each serial is 16 random bytes, positive, recorded, and revocable`, async () => {
            const location = path.join(testData.tmpFolder, `CA_random_${backend}`);
            const ca = new CertificateAuthority({ keySize: 2048, location, subject: `/CN=Random${backend}CA`, backend });
            await ca.initialize();

            const { serials, files } = await issue(ca, `PKI_random_${backend}`, 3);
            for (const serial of serials) {
                should(serial).match(/^[4-7][0-9A-F]{31}$/);
                should(ca.getCertificateStatus(serial)).eql("valid");
            }
            should(new Set(serials).size).eql(3, `distinct serials expected, got ${serials.join(",")}`);

            await ca.revokeCertificate(files[1], { reason: "keyCompromise" });
            should(ca.getCertificateStatus(serials[1])).eql("revoked");
            should(ca.getCertificateStatus(serials[0])).eql("valid");
        });
    }

    it("a CA re-created under the same name does not repeat the old CA's serials", async () => {
        const subject = "/CN=RecreatedCA";
        const first = new CertificateAuthority({ keySize: 2048, location: path.join(testData.tmpFolder, "CA_first"), subject });
        await first.initialize();
        const second = new CertificateAuthority({ keySize: 2048, location: path.join(testData.tmpFolder, "CA_second"), subject });
        await second.initialize();

        const before = (await issue(first, "PKI_first", 2)).serials;
        const after = (await issue(second, "PKI_second", 2)).serials;
        should(after.filter((s) => before.includes(s))).eql([]);
    });
});
