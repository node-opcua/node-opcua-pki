import { install_prerequisite } from "node-opcua-pki";

describe("testing install_prerequisite", () => {
    it("should verify prerequisite", async () => {
        await install_prerequisite();
    });
});
