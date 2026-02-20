import fs from "node:fs";
import path from "node:path";
import sinon from "sinon";
import "should";

import { readCertificate } from "node-opcua-crypto";
import { CertificateManager, type CertificateManagerOptions } from "../lib";
import { beforeTest } from "./helpers";

describe("Check Validate Certificate", function () {
    const testData = beforeTest(this);

    let clock: sinon.SinonFakeTimers;
    before(() => {
        clock = sinon.useFakeTimers({
            shouldAdvanceTime: true,
            now: new Date(2020, 1, 12).getTime()
        });
    });
    after(() => {
        clock.restore();
    });
    it("should verifyCertificateAsync", async () => {
        const options: CertificateManagerOptions = {
            location: path.join(testData.tmpFolder, "PKI")
        };
        const certificateManager = new CertificateManager(options);
        await certificateManager.initialize();

        const caCertificateFilename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I.der");
        const crlFilename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/crl/ctt_ca1I.crl");

        const cert1Filename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I_appT.der");
        const cert2Filename = path.join(__dirname, "fixtures/CTT_sample_certificates/CA/certs/ctt_ca1I_appTR.der");

        // installing the CA certificate
        const caCert = readCertificate(caCertificateFilename);
        let caCertStatus = await certificateManager.verifyCertificate(caCert);
        caCertStatus.should.eql("BadCertificateUntrusted");

        // installing the 1st cer
        const cert1 = fs.readFileSync(cert1Filename);
        const cert2 = fs.readFileSync(cert2Filename);
        await certificateManager.trustCertificate(cert1);
        await certificateManager.trustCertificate(cert2);

        {
            const cert1Status = await certificateManager.verifyCertificate(cert1);
            // should be -BadCertificateChainIncomplete because the issuer cert is not in the issuer list
            cert1Status.should.eql("BadCertificateChainIncomplete");
        }
        // installing the 2nd cert
        {
            const cert2Status = await certificateManager.verifyCertificate(cert2);
            // should be -BadCertificateChainIncomplete because the issuer cert is not in the issuer list
            cert2Status.should.eql("BadCertificateChainIncomplete");
        }

        // now move the caCert to the issue list
        const status = await certificateManager.addIssuer(caCert, true);
        status.should.eql("Good");
        caCertStatus = await certificateManager.verifyCertificate(caCert);
        caCertStatus.should.eql("BadCertificateUntrusted");

        {
            const cert1Status = await certificateManager.verifyCertificate(cert1);
            cert1Status.should.eql("BadCertificateRevocationUnknown");

            const cert1Status1 = await certificateManager.verifyCertificate(cert1, {});
            cert1Status1.should.eql("BadCertificateRevocationUnknown");

            const cert1Status2 = await certificateManager.verifyCertificate(cert1, { ignoreMissingRevocationList: true });
            cert1Status2.should.eql("Good");
        }
        //
        {
            const certEStatus = await certificateManager.verifyCertificate(cert2);
            certEStatus.should.eql("BadCertificateRevocationUnknown");
        }

        // now move the crl to the crl list
        const crl = fs.readFileSync(crlFilename);
        await certificateManager.addRevocationList(crl);
        {
            const cert1Status = await certificateManager.verifyCertificate(cert1);
            cert1Status.should.eql("Good");
        }
        {
            const cert2Status = await certificateManager.verifyCertificate(cert2);
            cert2Status.should.eql("BadCertificateRevoked");
        }
    });
});
