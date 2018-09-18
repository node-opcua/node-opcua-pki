import {ErrorCallback} from "../lib";
import {install_prerequisite} from "../lib/misc/install_prerequisite";

describe("testing install_prerequisite", () => {

    it("should verify prerequisite", (done: ErrorCallback) => {
        install_prerequisite((err: Error | null) => {
            done(err!);
        });
    });

});
