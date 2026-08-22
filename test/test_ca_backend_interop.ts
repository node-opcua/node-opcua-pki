import fs from "node:fs";
import path from "node:path";
import "should";
import { type CaSignAlgorithm, exploreCertificate, readCertificate } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager } from "node-opcua-pki";
import { execute_openssl } from "node-opcua-pki-priv/toolbox/with_openssl";
import { EC_P256_SHA256, makeLeafCsr, RSA_SHA256, StubHsmSigner } from "./_ca_backends";
import { beforeTest } from "./helpers";

/**
 * Properties that only exist *between* backends, or only appear under
 * load - neither belongs in a per-backend suite, because neither is about
 * one backend behaving correctly on its own.
 */
describe("CA backend interop", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    it("a CA created natively can afterwards be driven by openssl", async () => {
        // The reverse direction (openssl creates, native operates) is covered
        // in test_native_ca_backend. This is the one that proves a natively
        // bootstrapped directory is a real openssl CA directory: the config,
        // the key file, index.txt, serial and crlnumber all have to be
        // exactly what `openssl ca` expects to find.
        const location = path.join(testData.tmpFolder, "CA_native_then_openssl");
        await new CertificateAuthority({ keySize: 2048, location, subject: "/CN=HandoverCA", backend: "native" }).initialize();

        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=HandoverCA" });
        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_handover"), {
            applicationUri: "urn:test:handover"
        });
        const cert = path.join(cm.rootDir, "own/certs/signed.pem");
        await ca.signCertificateRequest(cert, csr, { applicationUri: "urn:test:handover", startDate: new Date(), validity: 30 });

        exploreCertificate(readCertificate(cert)).tbsCertificate.issuer.commonName?.should.eql("HandoverCA");
        await execute_openssl(["verify", "-CAfile", ca.caCertificate, cert], {});

        // and openssl's revocation path works on the natively created database
        await ca.revokeCertificate(cert, { reason: "keyCompromise" });
        let rejected = false;
        try {
            // expected to fail: hide the banner so a real openssl error still stands out
            await execute_openssl(["verify", "-CRLfile", ca.revocationList, "-CAfile", ca.caCertificate, "-crl_check", cert], {
                hideErrorMessage: true
            });
        } catch {
            rejected = true;
        }
        rejected.should.eql(true, "openssl must see the revocation it recorded itself");
        await cm.dispose();
    });

    it("concurrent issuance hands out distinct serials and loses no database row", async () => {
        // The directory lock is what makes this safe; nextSerial() is a
        // read-increment-write and appendIssued() an append, so a lost update
        // here would mean two certificates sharing a serial - which breaks
        // revocation, since the CRL identifies certificates by serial alone.
        const location = path.join(testData.tmpFolder, "CA_concurrent");
        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=ConcurrentCA", backend: "native" });
        await ca.initialize();

        const cm = new CertificateManager({ location: path.join(testData.tmpFolder, "PKI_concurrent") });
        await cm.initialize();
        const csr = await cm.createCertificateRequest({
            applicationUri: "urn:test:concurrent",
            subject: "CN=Concurrent",
            dns: ["localhost"]
        });

        const count = 8;
        const outputs = Array.from({ length: count }, (_, i) => path.join(cm.rootDir, `own/certs/signed_${i}.pem`));
        await Promise.all(
            outputs.map((out) =>
                ca.signCertificateRequest(out, csr, {
                    applicationUri: "urn:test:concurrent",
                    startDate: new Date(),
                    validity: 30
                })
            )
        );

        const serials = outputs.map((out) =>
            exploreCertificate(readCertificate(out)).tbsCertificate.serialNumber.replace(/:/g, "").toUpperCase()
        );
        new Set(serials).size.should.eql(count, `every certificate needs its own serial, got ${serials.join(",")}`);

        const records = ca.getIssuedCertificates();
        records.length.should.eql(count, "every issuance must leave exactly one index.txt row");
        new Set(records.map((r) => r.serial.toUpperCase())).size.should.eql(count);
        for (const serial of serials) {
            ca.getCertificateStatus(serial)?.should.eql("valid");
            (ca.getCertificateBySerial(serial)?.length ?? 0).should.be.greaterThan(0, `certs/${serial}.pem must exist`);
        }
        await cm.dispose();
    });

    it("issues the same certificate profile whichever backend does the signing", async () => {
        // The native backend is meant to be a drop-in for the openssl one,
        // and the extensions are where that quietly stops being true: they
        // come from a profile each backend builds separately, and no
        // per-backend test can notice that the two profiles disagree.
        //
        // It caught a real one. The native path was applying the *self-signed*
        // profile to CA-issued certificates, so every certificate it issued
        // carried keyCertSign - telling a validator the device may sign
        // certificates of its own - and lacked keyAgreement.
        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_profile"), {
            applicationUri: "urn:test:profile",
            dns: ["localhost"]
        });

        interface IssuedProfile {
            keyUsage: Record<string, boolean> | undefined;
            basicConstraints: unknown;
            extKeyUsage: unknown;
        }
        const profiles: Record<string, IssuedProfile> = {};
        for (const [label, options] of [
            ["openssl", { backend: "openssl" as const }],
            ["native", { backend: "native" as const }],
            ["native-signer-ec", { signer: await StubHsmSigner.create(EC_P256_SHA256) }]
        ] as const) {
            const location = path.join(testData.tmpFolder, `CA_profile_${label}`);
            const ca = new CertificateAuthority({ keySize: 2048, location, subject: `/CN=Profile${label}`, ...options });
            await ca.initialize();

            const out = path.join(cm.rootDir, `own/certs/profile_${label}.pem`);
            await ca.signCertificateRequest(out, csr, {
                applicationUri: "urn:test:profile",
                startDate: new Date(),
                validity: 30
            });
            const { extensions } = exploreCertificate(readCertificate(out)).tbsCertificate;
            profiles[label] = {
                keyUsage: extensions?.keyUsage as Record<string, boolean> | undefined,
                basicConstraints: extensions?.basicConstraints,
                extKeyUsage: extensions?.extKeyUsage
            };
        }

        // stated outright as well as compared, so a change made to both
        // backends at once still has to be a deliberate one
        const opensslKeyUsage = profiles.openssl.keyUsage;
        if (!opensslKeyUsage) {
            throw new Error("the openssl backend issued a certificate with no keyUsage extension");
        }
        opensslKeyUsage.keyCertSign.should.eql(false, "an issued end-entity certificate may not sign certificates of its own");
        opensslKeyUsage.keyAgreement.should.eql(true);

        profiles.native.should.eql(profiles.openssl, "the native backend must issue what the openssl backend issues");
        profiles["native-signer-ec"].should.eql(profiles.openssl, "an EC-keyed CA must issue the same profile too");
        await cm.dispose();
    });

    it("issues a chain from an EC-keyed CA that openssl accepts, CRL included", async () => {
        // The parameterized suite proves this package agrees with itself
        // about EC. openssl is the check that matters for anyone else: an
        // EC CA whose certificates only this library can verify would be
        // useless, and the failure would be silent from in here.
        const signer = await StubHsmSigner.create(EC_P256_SHA256);
        const location = path.join(testData.tmpFolder, "CA_ec_openssl");
        const ca = new CertificateAuthority({ keySize: 2048, location, subject: "/CN=EcInteropCA", signer });
        await ca.initialize();

        const { cm, csr } = await makeLeafCsr(path.join(testData.tmpFolder, "PKI_ec_interop"), {
            applicationUri: "urn:test:ec:interop"
        });
        const cert = path.join(cm.rootDir, "own/certs/ec_signed.pem");
        await ca.signCertificateRequest(cert, csr, {
            applicationUri: "urn:test:ec:interop",
            startDate: new Date(),
            validity: 30
        });

        const caCertificate = readCertificate(ca.caCertificate);
        exploreCertificate(caCertificate).tbsCertificate.subject.commonName?.should.eql("EcInteropCA");
        await execute_openssl(["verify", "-CAfile", ca.caCertificate, cert], {});

        // and openssl agrees the signature really is ECDSA rather than
        // something that merely happens to verify
        const text = await execute_openssl(["x509", "-in", ca.caCertificate, "-noout", "-text"], {});
        text.should.match(/ecdsa-with-SHA256/);
        text.should.match(/NIST CURVE: P-256/);

        // the CRL is signed by the same EC key, and is the artefact most
        // likely to be left behind on an RSA assumption
        await ca.revokeCertificate(cert, { reason: "keyCompromise" });
        let rejected = false;
        try {
            await execute_openssl(["verify", "-CRLfile", ca.revocationList, "-CAfile", ca.caCertificate, "-crl_check", cert], {
                hideErrorMessage: true
            });
        } catch {
            rejected = true;
        }
        rejected.should.eql(true, "openssl must see the revocation recorded by an EC-keyed CA");
        await cm.dispose();
    });

    it("refuses a signer nothing can consume, before touching the filesystem", async () => {
        // A signer arrives from untyped glue around a KMS SDK, so these are
        // reachable at runtime whatever the types say. Both must be refused
        // where the message can name the problem, and before any files
        // exist - not as a normalize-algorithm error thrown from inside
        // WebCrypto once the CA directory is already on disk.
        const location = path.join(testData.tmpFolder, "CA_bad_signer_alg");
        const ecKeys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

        // an ECDSA signer that never says which curve it is on
        const curveless = new StubHsmSigner(ecKeys, { name: "ECDSA", hash: { name: "SHA-256" } } as CaSignAlgorithm);
        (() => new CertificateAuthority({ keySize: 2048, location, subject: "/CN=Ec", signer: curveless })).should.throw(
            /must declare its namedCurve/
        );

        // an algorithm this CA has never heard of
        const nonsense = new StubHsmSigner(ecKeys, { name: "Ed25519" } as unknown as CaSignAlgorithm);
        (() => new CertificateAuthority({ keySize: 2048, location, subject: "/CN=Ed", signer: nonsense })).should.throw(
            /Ed25519 is not supported/
        );

        fs.existsSync(location).should.eql(false, "nothing may be created for a CA that cannot work");

        // both supported algorithms are accepted on the same path
        for (const [index, algorithm] of [RSA_SHA256, EC_P256_SHA256].entries()) {
            const signer = await StubHsmSigner.create(algorithm);
            (() =>
                new CertificateAuthority({
                    keySize: 2048,
                    location: path.join(testData.tmpFolder, `CA_good_signer_alg_${index}`),
                    subject: "/CN=Ok",
                    signer
                })).should.not.throw();
        }
    });
});
