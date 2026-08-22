import fs from "node:fs";
import path from "node:path";
import "should";
import { exploreCertificate, generateKeyPair, readCertificate, x509 } from "node-opcua-crypto";
import { CertificateAuthority } from "node-opcua-pki";
import { execute_openssl } from "node-opcua-pki-priv/toolbox/with_openssl";
import { makeLeafCsr } from "./_ca_backends";
import { beforeTest } from "./helpers";

// The native backend must produce a directory openssl itself can read: a CA
// bootstrapped with the default (openssl) backend, then signed/revoked with
// backend: "native", is verified below with the real `openssl` CLI — the
// same interop check the plan for this backend calls for.
describe("NativeCaBackend", function (this: Mocha.Suite) {
    this.timeout(120000);
    const testData = beforeTest(this);

    it("signs an end-entity CSR, revokes it, and regenerates the CRL — verified with real openssl", async () => {
        const location = path.join(testData.tmpFolder, "CA_native_backend");
        // bootstrap with the default (openssl) backend — bootstrap is not
        // part of the native backend yet, only signing/revocation is
        const bootstrapCa = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=NativeCA" });
        await bootstrapCa.initialize();

        // reopen the same directory with backend: "native" for signing/revocation
        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=NativeCA", backend: "native" });

        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_native_leaf"), {
            applicationUri: "urn:test:native-ca",
            subject: "CN=NativeLeaf"
        });
        const cert = path.join(cm.rootDir, "own/certs/signed.pem");
        await ca.signCertificateRequest(cert, csr, { applicationUri: "urn:test:native-ca", startDate: new Date(), validity: 30 });
        fs.existsSync(cert).should.eql(true);

        const info = exploreCertificate(readCertificate(cert));
        info.tbsCertificate.subject.commonName?.should.eql("NativeLeaf");
        info.tbsCertificate.issuer.commonName?.should.eql("NativeCA");
        info.tbsCertificate.extensions?.subjectAltName?.dNSName?.should.containEql("localhost");
        info.tbsCertificate.extensions?.subjectAltName?.uniformResourceIdentifier?.should.containEql("urn:test:native-ca");

        // openssl must accept this certificate as validly chained to the CA
        await execute_openssl(["verify", "-verbose", "-CAfile", ca.caCertificate, cert], {});

        // index.txt must carry a V (valid) row for this certificate — the
        // same on-disk format the openssl backend writes
        fs.readFileSync(path.join(location, "index.txt"), "utf-8").should.match(/^V\t/m);

        await ca.revokeCertificate(cert, { reason: "keyCompromise" });
        fs.readFileSync(path.join(location, "index.txt"), "utf-8").should.match(
            /^R\t.*keyCompromise/m,
            "index.txt must record the revocation with its reason"
        );

        // real openssl must see the CRL, and see this certificate as revoked on it
        const crlText = await execute_openssl(["crl", "-in", ca.revocationList, "-text", "-noout"], {});
        crlText.should.containEql("CRL Number");
        crlText.should.containEql("Key Compromise");

        let verifyThrew = false;
        try {
            await execute_openssl(
                ["verify", "-verbose", "-CRLfile", ca.revocationList, "-CAfile", ca.caCertificate, "-crl_check", cert],
                // expected to fail: hide the banner so a real openssl error still stands out
                { hideErrorMessage: true }
            );
        } catch {
            verifyThrew = true;
        }
        verifyThrew.should.eql(true, "openssl must reject the now-revoked certificate under -crl_check");

        await cm.dispose();
    });

    it("regenerateCrl produces an empty-but-valid CRL openssl can read", async () => {
        const location = path.join(testData.tmpFolder, "CA_native_empty_crl");
        const bootstrapCa = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=NativeEmptyCA" });
        await bootstrapCa.initialize();

        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=NativeEmptyCA", backend: "native" });
        await ca.regenerateCrl();

        const crlText = await execute_openssl(["crl", "-in", ca.revocationList, "-text", "-noout"], {});
        crlText.should.containEql("CRL Number");
        await execute_openssl(["crl", "-in", ca.revocationList, "-CAfile", ca.caCertificate, "-noout"], {});
    });

    it("a CSR subject carrying newlines/tabs cannot inject a forged row into index.txt (unauthorized revocation)", async () => {
        // index.txt is a tab/newline-delimited table, and the subject comes
        // verbatim from the requester's CSR. A CN containing a raw "\n"
        // followed by an attacker-authored "R" row would otherwise be
        // appended as a second, real-looking record naming a victim's
        // (sequential, guessable) serial — and the next CRL regeneration,
        // which runs right after every signing, would publish that serial
        // as revoked. peculiar/x509's string escaping only covers the FIRST
        // control character per value, so this payload uses two.
        const location = path.join(testData.tmpFolder, "CA_native_inject");
        const bootstrapCa = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=InjectCA" });
        await bootstrapCa.initialize();
        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=InjectCA", backend: "native" });

        // a legitimate victim certificate first: it takes serial 1000
        const { cm: victimCm, csr: victimCsr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_native_victim"), {
            applicationUri: "urn:test:native-ca",
            subject: "CN=NativeLeaf"
        });
        const victimCert = path.join(victimCm.rootDir, "own/certs/signed.pem");
        await ca.signCertificateRequest(victimCert, victimCsr, {
            applicationUri: "urn:test:native-ca",
            startDate: new Date(),
            validity: 30
        });
        const victimSerial = exploreCertificate(readCertificate(victimCert))
            .tbsCertificate.serialNumber.replace(/:/g, "")
            .toUpperCase();

        // the attacker's CSR: CN ends with a forged "R" row for the victim's serial
        const forgedRow = `R\t300101000000Z\t260101000000Z\t${victimSerial}\tunknown\t/CN=victim`;
        const hostileCn = `evil\n\n${forgedRow}`;
        // built directly with peculiar/x509 from a structured name: an
        // attacker crafts their own CSR, and the string-parsing paths
        // (openssl -subj, Subject) would otherwise mangle the payload
        const attackerDir = path.join(testData.tmpFolder, "PKI_native_attacker");
        fs.mkdirSync(attackerDir, { recursive: true });
        const attackerKeys = await generateKeyPair();
        const hostileCsr = await x509.Pkcs10CertificateRequestGenerator.create({
            name: [{ CN: [hostileCn] }],
            keys: attackerKeys,
            signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
            extensions: [
                new x509.SubjectAlternativeNameExtension([
                    { type: "url", value: "urn:test:native-ca:attacker" },
                    { type: "dns", value: "localhost" }
                ])
            ]
        });
        new x509.Pkcs10CertificateRequest(hostileCsr.rawData).subjectName.getField("CN")[0].should.eql(hostileCn);
        const attackerCsr = path.join(attackerDir, "hostile.csr");
        fs.writeFileSync(attackerCsr, hostileCsr.toString("pem"));
        const attackerCert = path.join(attackerDir, "signed.pem");
        await ca.signCertificateRequest(attackerCert, attackerCsr, {
            applicationUri: "urn:test:native-ca:attacker",
            startDate: new Date(),
            validity: 30
        });

        // exactly two records (victim + attacker), both valid, and no raw
        // control character survived into the database file
        const index = fs.readFileSync(path.join(location, "index.txt"), "utf-8");
        const rows = index.split("\n").filter((l) => l.length > 0);
        rows.length.should.eql(2, `index.txt must hold exactly 2 rows, got:\n${index}`);
        rows.every((r) => r.startsWith("V\t")).should.eql(true, "no row may have been forged as revoked");
        // the payload survives only as escaped text inside the attacker's own row
        // control characters must be \xHH-escaped, never raw
        rows[1].includes("/CN=evil\\x0A\\x0AR\\x09").should.eql(true, rows[1]);
        index.split("\t").length.should.eql(1 + 2 * 5, "exactly 5 tabs per row: none injected");
        ca.getCertificateStatus(victimSerial)?.should.eql("valid");
        ca.getIssuedCertificates().length.should.eql(2);

        // the CRL must not list the victim
        const crlText = await execute_openssl(["crl", "-in", ca.revocationList, "-text", "-noout"], {});
        crlText.should.containEql("No Revoked Certificates");
        await execute_openssl(["verify", "-CRLfile", ca.revocationList, "-CAfile", ca.caCertificate, "-crl_check", victimCert], {});

        // and the victim is still revocable by its legitimate owner/operator
        await ca.revokeCertificate(victimCert, { reason: "keyCompromise" });
        ca.getCertificateStatus(victimSerial)?.should.eql("revoked");

        await victimCm.dispose();
    });
});
