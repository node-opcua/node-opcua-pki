import fs, { mkdirSync } from "node:fs";
import path from "node:path";
import { CertificatePurpose } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager } from "node-opcua-pki";
import { createCertificateSigningRequestWithOpenSSL } from "node-opcua-pki-priv/toolbox/with_openssl/create_certificate_signing_request";
import { createCertificateSigningRequestAsync as createCertificateSigningRequestAsyncWithoutOpenSSL } from "node-opcua-pki-priv/toolbox/without_openssl";
import { beforeTest } from "./helpers";

describe("comparing two implementations of createCertificateSigningRequestAsync", function (this: Mocha.Suite) {
    // Called here, in the describe body, like every other test file - NOT from inside a
    // `before` hook. beforeTest() registers a `before` of its own, and doing that at run
    // time appends a hook to a suite mocha has already built: the hook never runs, but
    // its 5-minute timeout is armed and never cleared, so the process sits for 300s after
    // the suite passes and then dies with ERR_MOCHA_MULTIPLE_DONE.
    //
    // Registering it first also matters: its `before` wipes tmp/, and it has to run
    // BEFORE the hook below that creates the PKI under tmp/ - otherwise the cleanup
    // deletes the private key these tests depend on.
    const testData = beforeTest(this);

    const rootDir = path.join(__dirname, "../tmp/certificates/PKI-2");
    const configFile = path.join(rootDir, "own/openssl.cnf");
    const privateKey = path.join(rootDir, "own/private/private_key.pem");

    let certificateManager: CertificateManager;

    before(async () => {
        const options = {
            location: rootDir
        };

        mkdirSync(rootDir, { recursive: true });

        certificateManager = new CertificateManager(options);

        await certificateManager.initialize();
    });

    // initialize() starts chokidar watchers. chokidar v4 does not propagate
    // persistent:false down to the underlying fs.watch handles, so an undisposed
    // manager keeps the event loop alive and the process never exits - the suite
    // passes and then hangs. Every other test file disposes; this one did not.
    after(async () => {
        await certificateManager.dispose();
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
            purpose: CertificatePurpose.ForApplication
        });

        await createCertificateSigningRequestWithOpenSSL(csr2, {
            rootDir,
            configFile,
            privateKey,
            applicationUri,
            dns,
            ip,
            subject,
            purpose: CertificatePurpose.ForApplication
        });

        //  openssl req -text -noout -verify -in server.csr
    });

    describe("createCertificateSigningRequestAsync", () => {
        let theCertificateAuthority: CertificateAuthority;
        before(async () => {
            theCertificateAuthority = new CertificateAuthority({
                keySize: 2048,
                location: path.join(testData.tmpFolder, "CA")
            });
            await theCertificateAuthority.initialize();
        });
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
                purpose: CertificatePurpose.ForApplication
            });

            const params = {
                applicationUri: "BAD SHOULD BE IN REQUEST",
                startDate: new Date(2011, 25, 12),
                validity: 10 * 365
            };

            const certificateFilename = path.join(rootDir, "cert1.pem");
            if (fs.existsSync(certificateFilename)) {
                fs.unlinkSync(certificateFilename);
            }
            await theCertificateAuthority.signCertificateRequest(certificateFilename, certificateSigningRequestFilename, params);
        });
    });
});
