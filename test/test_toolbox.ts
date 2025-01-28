import fs from "fs";
import path from "path";
import "should";

import { mkdir, warningLog } from "../lib";
import { getPublicKeyFromCertificate, getPublicKeyFromPrivateKey } from "../lib/toolbox/with_openssl";
import { beforeTest } from "./helpers";
import { generatePrivateKeyFile } from "node-opcua-crypto";

describe("testing NodeOPCUA PKI Toolbox", function (this: Mocha.Suite) {
    this.timeout(400000);

    const testData = beforeTest(this);

    let privateKey: string;
    before(async () => {
        
        privateKey = path.join(testData.tmpFolder, "some_private_key");
        await mkdir(testData.tmpFolder);

        warningLog("generating private key");
        await generatePrivateKeyFile(privateKey, 2048);
        fs.existsSync(privateKey).should.eql(true);
        warningLog("privateKey = ", privateKey);
    });

    it("should getPublicKeyFromPrivateKey", async () => {
        
        const publicKey = path.join(testData.tmpFolder, "some_public_key");


        warningLog("get public public key from private key");
        await getPublicKeyFromPrivateKey(privateKey, publicKey);
        warningLog("publicKey = ", publicKey);
        fs.existsSync(publicKey).should.eql(true);

        const data = fs.readFileSync(publicKey, "ascii");

        data.should.match(/-----BEGIN PUBLIC KEY-----/);
        data.should.match(/-----END PUBLIC KEY-----/);

    });

    it("should getPublicKeyFromCertificate",async () => {
        const sampleCertificate = path.join(__dirname, "fixtures/sample_self_signed_certificate.pem");
        const publicKey = path.join(testData.tmpFolder, "some_public_key2");

        await getPublicKeyFromCertificate(sampleCertificate, publicKey);
        fs.existsSync(publicKey).should.eql(true);

        const data = fs.readFileSync(publicKey, "ascii");
        data.should.match(/-----BEGIN PUBLIC KEY-----/);
        data.should.match(/-----END PUBLIC KEY-----/);

        data.should.match(/-----BEGIN CERTIFICATE-----/);
        data.should.match(/-----END CERTIFICATE-----/);

    });
});
