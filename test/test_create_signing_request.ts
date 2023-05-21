import * as path from "path";
import * as fs from "fs";
import { createCertificateSigningRequestAsync as createCertificateSigningRequestAsyncWithoutOpenSSL } from "../lib/toolbox/without_openssl";
import { createCertificateSigningRequestAsync as createCertificateSigningRequestAsyncWithOpenSSL } from "../lib/toolbox/with_openssl";
import { CertificateManager } from "../lib/pki/certificate_manager";
import { mkdirSync } from "fs";
import { CertificatePurpose } from "node-opcua-crypto";
import { beforeTest } from "./helpers";
import { CertificateAuthority } from "../lib/ca";

describe("comparing two implementations of createCertificateSigningRequestAsync", function () {
    const rootDir = path.join(__dirname, "../tmp/certificates/PKI-2");
    const configFile = path.join(rootDir, "own/openssl.cnf");
    const privateKey = path.join(rootDir, "own/private/private_key.pem");
    before(async () => {
        const options = {
            location: rootDir,
        };
        
        mkdirSync(rootDir, { recursive: true });

        const cm = new CertificateManager(options);

        await cm.initialize();
    });
    it("should product identical results (or sufficiently identical)", async () => {
        const applicationUri = "urn:localhost:MyProduct";
        const dns = ["localhost", "my.domain.com"];
        const ip = ["192.168.1.1"];
        const subject = "/C=FR/ST=IDF/L=Paris/O=MyOrganization/OU=MyDepartment/CN=MyCommonName";

        const csr1 = path.join(__dirname, "../tmp/without_openssl.csr");
        const csr2 = path.join(__dirname, "../tmp/with_openssl.csr");

        await createCertificateSigningRequestAsyncWithoutOpenSSL(csr1, {
            rootDir,
            configFile,
            privateKey,
            applicationUri,
            dns,
            ip,
            subject,
            purpose: CertificatePurpose.ForApplication,
        });

        await createCertificateSigningRequestAsyncWithOpenSSL(csr2, {
            rootDir,
            configFile,
            privateKey,
            applicationUri,
            dns,
            ip,
            subject,
            purpose: CertificatePurpose.ForApplication,
        });

        //  openssl req -text -noout -verify -in server.csr
    });



    describe("createCertificateSigningRequestAsync", () => {

        let theCertificateAuthority: CertificateAuthority;
        before(async()=>{
                const testData = beforeTest(this);
             theCertificateAuthority = new CertificateAuthority({
                keySize: 2048,
                location: path.join(testData.tmpFolder, "CA"),
            });
            await theCertificateAuthority.initialize();

        })
        it("should be possible to create a certificate from a createCertificateSigningRequestAsync  created without openssl )", async () => {
        
            const applicationUri = "urn:localhost:MyProduct";
            const dns = ["localhost", "my.domain.com"];
            const ip = ["192.168.1.1"];
            const subject = "/C=FR/ST=IDF/L=Paris/O=MyOrganization/OU=MyDepartment/CN=MyCommonName";

            const certificateSigningRequestFilename = path.join(__dirname, "../tmp/without_openssl.csr");

            await createCertificateSigningRequestAsyncWithoutOpenSSL(certificateSigningRequestFilename, {
                rootDir,
                configFile,
                privateKey,
                applicationUri,
                dns,
                ip,
                subject,
                purpose: CertificatePurpose.ForApplication,
            });

            const params = {
                applicationUri: "BAD SHOULD BE IN REQUEST",
                startDate: new Date(2011, 25, 12),
                validity: 10 * 365,
            };

            const certificateFilename = path.join(rootDir, "cert1.pem");
            if (fs.existsSync(certificateFilename)) {
                fs.unlinkSync(certificateFilename);
            }
            await theCertificateAuthority.signCertificateRequest(certificateFilename, certificateSigningRequestFilename, params);
        });
    });
   
});
