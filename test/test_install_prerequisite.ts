import { install_prerequisite } from "../lib/toolbox/with_openssl/install_prerequisite";

describe("testing install_prerequisite", () => {

    it("should verify prerequisite", async () => {
        await install_prerequisite();
    });

});
