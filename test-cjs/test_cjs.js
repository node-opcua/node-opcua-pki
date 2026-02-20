const fs = require("node:fs");
const assert = require("node:assert");
const { CertificateManager } = require("node-opcua-pki");

async function main() {
    const cm = new CertificateManager({
        location: "./tmp/pki_cjs"
    });
    await cm.initialize();

    const outputFile = "./tmp/pki_cjs/my_cert.pem";
    if (fs.existsSync(outputFile)) {
        fs.unlinkSync(outputFile);
    }

    await cm.createSelfSignedCertificate({
        applicationUri: "urn:NodeOPCUA-Server-CJS",
        subject: "/CN=NodeOPCUA-CJS/O=Sterfive/L=Paris",
        dns: ["localhost"],
        startDate: new Date(),
        validity: 365,
        outputFile
    });

    assert(fs.existsSync(outputFile), "Certificate should exist");
    console.log("CJS Test: CertificateManager initialized successfully and created a certificate.");
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
