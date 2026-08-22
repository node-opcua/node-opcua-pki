import fs from "node:fs";
import path from "node:path";
import "should";
import { exploreCertificate, readCertificate, x509 } from "node-opcua-crypto";
import { CertificateAuthority } from "node-opcua-pki";
import { execute_openssl } from "node-opcua-pki-priv/toolbox/with_openssl";
import { makeLeafCsr, StubHsmSigner } from "./_ca_backends";
import { beforeTest } from "./helpers";

describe("NativeCaBackend bootstrap", function (this: Mocha.Suite) {
    this.timeout(200000);
    const testData = beforeTest(this);

    it("creates a root CA end to end without openssl, and openssl accepts the result", async () => {
        const location = path.join(testData.tmpFolder, "CA_native_root");
        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=NativeRoot", backend: "native" });
        await ca.initialize();

        fs.existsSync(ca.caCertificate).should.eql(true);
        fs.existsSync(ca.revocationList).should.eql(true, "the initial CRL must exist");

        const info = exploreCertificate(readCertificate(ca.caCertificate));
        info.tbsCertificate.subject.commonName?.should.eql("NativeRoot");
        info.tbsCertificate.issuer.commonName?.should.eql("NativeRoot");
        info.tbsCertificate.extensions?.basicConstraints?.cA.should.eql(true);
        info.tbsCertificate.extensions?.keyUsage?.keyCertSign.should.eql(true);
        info.tbsCertificate.extensions?.keyUsage?.cRLSign.should.eql(true);
        info.tbsCertificate.extensions?.subjectAltName?.uniformResourceIdentifier?.should.containEql("urn:NativeRoot");

        // openssl must agree it is a well-formed, self-consistent root
        await execute_openssl(["verify", "-CAfile", ca.caCertificate, ca.caCertificate], {});
        await execute_openssl(["crl", "-in", ca.revocationList, "-CAfile", ca.caCertificate, "-noout"], {});

        // and it can actually issue
        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_native_root_leaf"), {
            applicationUri: "urn:test:native-root"
        });
        const cert = path.join(cm.rootDir, "own/certs/signed.pem");
        await ca.signCertificateRequest(cert, csr, { applicationUri: "urn:test:native-root", startDate: new Date(), validity: 30 });
        await execute_openssl(["verify", "-CAfile", ca.caCertificate, cert], {});
        await cm.dispose();
    });

    it("signs with an HSM-held key that is never written to disk", async () => {
        const location = path.join(testData.tmpFolder, "CA_hsm_root");
        const signer = await StubHsmSigner.create();
        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=HsmRoot", signer });

        ca.hasExternalSigner.should.eql(true);
        await ca.initialize();

        // the whole point: no key material ever reached the filesystem
        fs.existsSync(ca.privateKey).should.eql(false, "a signer-backed CA must never write private/cakey.pem");
        signer.signCalls.should.be.greaterThan(0, "the CA certificate and CRL must have gone through the signer");

        await execute_openssl(["verify", "-CAfile", ca.caCertificate, ca.caCertificate], {});

        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_hsm_leaf"), { applicationUri: "urn:test:hsm" });
        const cert = path.join(cm.rootDir, "own/certs/signed.pem");
        const before = signer.signCalls;
        await ca.signCertificateRequest(cert, csr, { applicationUri: "urn:test:hsm", startDate: new Date(), validity: 30 });
        signer.signCalls.should.be.greaterThan(before, "issuing must go through the signer too");
        fs.existsSync(ca.privateKey).should.eql(false);

        exploreCertificate(readCertificate(cert)).tbsCertificate.issuer.commonName?.should.eql("HsmRoot");
        await execute_openssl(["verify", "-CAfile", ca.caCertificate, cert], {});

        // revocation and the CRL are signed the same way
        await ca.revokeCertificate(cert, { reason: "keyCompromise" });
        const crlText = await execute_openssl(["crl", "-in", ca.revocationList, "-text", "-noout"], {});
        crlText.should.containEql("Key Compromise");
        let rejected = false;
        try {
            // expected to fail: hide the banner so a real openssl error still stands out
            await execute_openssl(["verify", "-CRLfile", ca.revocationList, "-CAfile", ca.caCertificate, "-crl_check", cert], {
                hideErrorMessage: true
            });
        } catch {
            rejected = true;
        }
        rejected.should.eql(true, "openssl must reject the revoked certificate");
        fs.existsSync(ca.privateKey).should.eql(false);
        await cm.dispose();
    });

    it("builds a root to subordinate chain natively, recording the sub-CA in the issuer's database", async () => {
        const rootLocation = path.join(testData.tmpFolder, "CA_native_chain_root");
        const root = new CertificateAuthority({
            keySize: 2048,
            location: rootLocation,
            subject: "/CN=ChainRoot",
            backend: "native"
        });
        await root.initialize();

        const subLocation = path.join(testData.tmpFolder, "CA_native_chain_sub");
        const sub = new CertificateAuthority({
            keySize: 2048,
            location: subLocation,
            subject: "/CN=ChainSub",
            issuerCA: root,
            backend: "native"
        });
        await sub.initialize();

        const subInfo = exploreCertificate(readCertificate(sub.caCertificate));
        subInfo.tbsCertificate.subject.commonName?.should.eql("ChainSub");
        subInfo.tbsCertificate.issuer.commonName?.should.eql("ChainRoot");
        subInfo.tbsCertificate.extensions?.basicConstraints?.cA.should.eql(true);
        // the openssl backend stamps the issuer's own SAN here because it never
        // parses the subordinate's CSR; the native one carries the real one
        subInfo.tbsCertificate.extensions?.subjectAltName?.uniformResourceIdentifier?.should.containEql("urn:ChainSub");

        // recorded in the ISSUER's database - openssl's x509 -CAserial path records nothing
        const rootIndex = root.getIssuedCertificates();
        rootIndex.length.should.eql(1, "the subordinate must appear in the root's index.txt");
        rootIndex[0].subject.should.containEql("ChainSub");

        // a leaf issued by the subordinate chains all the way to the root
        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_native_chain_leaf"), {
            applicationUri: "urn:test:chain"
        });
        const cert = path.join(cm.rootDir, "own/certs/signed.pem");
        await sub.signCertificateRequest(cert, csr, { applicationUri: "urn:test:chain", startDate: new Date(), validity: 30 });
        await execute_openssl(["verify", "-CAfile", root.caCertificate, "-untrusted", sub.caCertificate, cert], {});
        await cm.dispose();
    });

    it("rejects a signer combined with the openssl backend, and the key-file operations it cannot serve", async () => {
        const location = path.join(testData.tmpFolder, "CA_signer_guards");
        const signer = await StubHsmSigner.create();

        (() => new CertificateAuthority({ keySize: 2048, location, subject: "/CN=X", signer, backend: "openssl" })).should.throw(
            /cannot be combined/
        );

        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=Guards", signer });
        await ca.initialize();

        await ca.getPrivateKey().should.be.rejectedWith(/not available on a signer-backed CA/);
        await ca.reencryptPrivateKey(undefined, "new").should.be.rejectedWith(/not available on a signer-backed CA/);
    });

    it("produces a CSR for an externally-signed CA without writing a key, and stays pending across restarts", async () => {
        const location = path.join(testData.tmpFolder, "CA_signer_csr");
        const signer = await StubHsmSigner.create();
        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=ExternallySigned", signer });

        const created = await ca.initializeCSR();
        created.status.should.eql("created");
        fs.existsSync(ca.privateKey).should.eql(false, "still no key file");

        const csrPath = (created as { csrPath: string }).csrPath;
        // openssl must be able to read it (interop), but the signature is
        // checked in-process: `req -verify`'s wording and exit code differ
        // between OpenSSL releases, so asserting on them is not portable
        const csrText = await execute_openssl(["req", "-in", csrPath, "-noout", "-subject"], {});
        csrText.should.containEql("ExternallySigned");
        const request = new x509.Pkcs10CertificateRequest(fs.readFileSync(csrPath, "utf-8"));
        (await request.verify()).should.eql(true, "the CSR must carry a valid proof of possession");

        // a restart before the external signature arrives must not regenerate:
        // without the signer being recognised as "key available" this fell
        // through to the fresh-setup branch and issued a second CSR
        const before = fs.readFileSync(csrPath, "utf-8");
        const again = await new CertificateAuthority({
            keySize: 2048,
            location,
            subject: "/CN=ExternallySigned",
            signer
        }).initializeCSR();
        again.status.should.eql("pending");
        fs.readFileSync(csrPath, "utf-8").should.eql(before, "the pending CSR must be left alone");
    });
});
