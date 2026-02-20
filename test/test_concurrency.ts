import path from "node:path";
import "should";
import { CertificateManager } from "../lib";
import { beforeTest } from "./helpers";

describe("Concurrency", function (this: Mocha.Suite) {
    const testData = beforeTest(this);

    it("should not crash if multiple CertificateManager instances share the same folder", async () => {
        const location = path.join(testData.tmpFolder, "concurrency");

        const workWithCertificateManager = async (n: number) => {
            const cm1 = new CertificateManager({
                location
            });
            console.log("starting ", n);
            await cm1.initialize();
            const now = new Date();
            const _endDate = new Date(now.getFullYear() + 7, 10, 10);
            const duration = 10000;

            const params = {
                applicationUri: "MY:APPLICATION:URI",
                dns: ["some.other.domain.com", "my.domain.com"],
                ip: ["192.123.145.121"],
                subject: "/CN=MyCommonName",
                // can only be TODAY due to openssl limitation : startDate: new Date(2010,2,2),
                validity: duration,
                startDate: now
            };
            await cm1.createSelfSignedCertificate(params);

            console.log("ah!", n);
        };

        const promises = [
            workWithCertificateManager(1),
            workWithCertificateManager(2),
            workWithCertificateManager(3),
            workWithCertificateManager(4)
        ];
        await Promise.all(promises);
    });
});
