import assert from "node:assert";
import fs from "node:fs";

import { CertificateManager } from "node-opcua-pki";

async function main() {
    const cm = new CertificateManager({
        location: "./tmp/pki_esm"
    });
    await cm.initialize();

    const outputFile = "./tmp/pki_esm/my_cert.pem";
    if (fs.existsSync(outputFile)) {
        fs.unlinkSync(outputFile);
    }

    await cm.createSelfSignedCertificate({
        applicationUri: "urn:NodeOPCUA-Server-ESM",
        subject: "/CN=NodeOPCUA-ESM/O=Sterfive/L=Paris",
        dns: ["localhost"],
        startDate: new Date(),
        validity: 365,
        outputFile
    });

    assert(fs.existsSync(outputFile), "Certificate should exist");

    console.log("ESM Test: CertificateManager initialized successfully via import and created a certificate.");
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
