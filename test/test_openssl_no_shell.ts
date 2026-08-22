import fs from "node:fs";
import path from "node:path";
import "should";
import { exploreCertificate, readCertificate } from "node-opcua-crypto";
import { CertificateAuthority, CertificateManager } from "node-opcua-pki";
import { cleanupStaticConfig, execute_openssl, generateStaticConfig } from "node-opcua-pki-priv/toolbox/with_openssl";
import { beforeTest } from "./helpers";

// openssl is spawned without a shell: every argv element reaches it as-is.
// These tests use values that a shell would have expanded, split, or
// executed, and assert they are handled literally instead.
describe("openssl is invoked without a shell", function (this: Mocha.Suite) {
    this.timeout(60000);
    const testData = beforeTest(this);

    // `"` is not allowed in Windows paths; everything else here is legal on
    // every platform and meaningful to sh and cmd.exe alike.
    const hostile = "$(echo injected) `whoami` & rem ; | > out.txt";
    // `|` and `>` are illegal in Windows file names: a path-safe subset for locations
    const hostilePath = "$(echo injected) `whoami` & rem ;";
    const marker = "injected";

    it("a subject containing shell metacharacters is passed to openssl verbatim", async () => {
        const location = path.join(testData.tmpFolder, "PKI_no_shell_subject");
        const cm = new CertificateManager({ location });
        await cm.initialize();
        const subject = `CN=${hostile}`;
        await cm.createSelfSignedCertificate({
            applicationUri: "urn:test:no-shell",
            subject,
            dns: ["localhost"],
            startDate: new Date(),
            validity: 365
        });
        const certFile = path.join(location, "own/certs/self_signed_certificate.pem");
        const info = exploreCertificate(readCertificate(certFile));
        info.tbsCertificate.subject.commonName?.should.eql(hostile);
        fs.existsSync(path.join(location, "out.txt")).should.eql(false, "`>` must not have created a file");
        await cm.dispose();
    });

    it("a PKI location containing shell metacharacters works end to end (CA + revoke + CRL)", async () => {
        // The CA embeds its location in caconfig.cnf: it is double-quoted and
        // escaped there (renderCaConfig), so characters openssl's own config
        // parser would otherwise interpret ($(...) expansion, backtick quoting,
        // `#` comments) are taken literally too.
        const caLocation = path.join(testData.tmpFolder, `CA ${hostilePath} # not a comment`);
        const ca = new CertificateAuthority({ keySize: 2048, location: caLocation, subject: "/CN=NoShellCA" });
        await ca.initialize();
        fs.existsSync(ca.caCertificate).should.eql(true);

        const cmLocation = path.join(testData.tmpFolder, `PKI ${hostilePath}`);
        const cm = new CertificateManager({ location: cmLocation });
        await cm.initialize();
        const csr = await cm.createCertificateRequest({
            applicationUri: "urn:test:no-shell:ca",
            subject: "CN=Leaf",
            dns: ["localhost"]
        });
        const cert = path.join(cmLocation, "own/certs/signed.pem");
        await ca.signCertificateRequest(cert, csr, { applicationUri: "urn:test:no-shell:ca", startDate: new Date(), validity: 30 });
        fs.existsSync(cert).should.eql(true);

        await ca.revokeCertificate(cert, { reason: "keyCompromise" });
        fs.existsSync(ca.revocationList).should.eql(true);

        // the literal names exist (nothing was expanded) and no `>` redirection ran
        fs.existsSync(path.join(cmLocation, "own/private/private_key.pem")).should.eql(true);
        fs.existsSync(path.join(caLocation, "private/cakey.pem")).should.eql(true);
        for (const dir of [caLocation, cmLocation, testData.tmpFolder]) {
            fs.readdirSync(dir).includes("out.txt").should.eql(false, dir);
            fs.readdirSync(dir).includes(marker).should.eql(false, dir);
        }
        await cm.dispose();
    });

    it("execute_openssl passes each argv element literally", async () => {
        // `-subj` value with metacharacters, read back through openssl itself
        const location = path.join(testData.tmpFolder, "PKI_no_shell_argv");
        const cm = new CertificateManager({ location });
        await cm.initialize();
        const out = await execute_openssl(
            ["req", "-new", "-batch", "-key", cm.privateKey, "-subj", `/CN=${hostile}`, "-noout", "-text"],
            { cwd: location }
        );
        out.should.containEql(hostile);
        await cm.dispose();
    });

    it("config rendering substitutes values containing replacement-pattern characters ($&, $$) literally", async () => {
        // `$&`, `$$`, "$`" are String.replace replacement patterns: when the
        // renderer used the string form of replace, a value containing `$&`
        // re-inserted the matched `$ENV::NAME` literal into the rendered
        // config, and every signing operation on that CA then failed with
        // openssl's "variable has no value". This pins the renderer's
        // function-form fix. (openssl's own config syntax separately rejects
        // unquoted `$` in values, so such characters in a CDP URL still fail
        // at the openssl layer — a pre-existing, documented limitation of the
        // config template, not of the renderer.)
        const caLocation = path.join(testData.tmpFolder, "CA_dollar_render");
        const ca = new CertificateAuthority({ keySize: 2048, location: caLocation, subject: "/CN=DollarRenderCA" });
        await ca.initialize();

        const hostileValue = "URI:urn:Acme$&$$Co$`x";
        const rendered = generateStaticConfig(
            "conf/caconfig.cnf",
            { cwd: caLocation },
            { ALTNAME: hostileValue, CDP_URL: "http://crl.example.com/a$&b.crl", AIA_VALUE: "" }
        );
        try {
            const content = fs.readFileSync(path.join(caLocation, rendered), "utf-8");
            content.should.containEql(hostileValue);
            content.should.containEql("http://crl.example.com/a$&b.crl");
            content.includes("$ENV::").should.eql(false, "no substitution placeholder may survive or be re-inserted");
        } finally {
            await cleanupStaticConfig(rendered, { cwd: caLocation });
        }
    });
});
