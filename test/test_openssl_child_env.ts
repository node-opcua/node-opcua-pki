import "should";
import { buildChildEnv, redactEnvForLog, SAFE_ENV_PASSTHROUGH } from "node-opcua-pki-priv/toolbox/with_openssl/_env";

describe("openssl child process environment", () => {
    it("buildChildEnv should pass through only allowlisted variables plus the per-call extras", () => {
        const saved = { ...process.env };
        try {
            process.env.NODE_OPCUA_TEST_SECRET_TOKEN = "must-not-leak";
            process.env.LD_LIBRARY_PATH = "/opt/openssl/lib";
            const env = buildChildEnv({ NODE_OPCUA_PKI_OPENSSL_PASSIN: "pass" });
            (env.NODE_OPCUA_TEST_SECRET_TOKEN === undefined).should.eql(true, "unrelated host secrets must not reach the child");
            env.LD_LIBRARY_PATH!.should.eql("/opt/openssl/lib");
            env.NODE_OPCUA_PKI_OPENSSL_PASSIN!.should.eql("pass");
            for (const key of Object.keys(env)) {
                if (key === "NODE_OPCUA_PKI_OPENSSL_PASSIN") continue;
                SAFE_ENV_PASSTHROUGH.has(key.toLowerCase()).should.eql(true, `unexpected passthrough: ${key}`);
            }
        } finally {
            delete process.env.NODE_OPCUA_TEST_SECRET_TOKEN;
            if (saved.LD_LIBRARY_PATH === undefined) delete process.env.LD_LIBRARY_PATH;
            else process.env.LD_LIBRARY_PATH = saved.LD_LIBRARY_PATH;
        }
    });

    it("the allowlist should include the dynamic-loader variables a relocated openssl needs", () => {
        for (const v of [
            "ld_library_path",
            "dyld_library_path",
            "dyld_fallback_library_path",
            "openssl_engines",
            "openssl_modules"
        ]) {
            SAFE_ENV_PASSTHROUGH.has(v).should.eql(true, v);
        }
    });

    it("redactEnvForLog should keep env variable names but never their values", () => {
        const options = { cwd: "/x", hideErrorMessage: false, env: { NODE_OPCUA_PKI_OPENSSL_PASSIN: "s3cret" } };
        const redacted = redactEnvForLog(options);
        JSON.stringify(redacted).should.not.match(/s3cret/);
        redacted.env!.should.eql(["NODE_OPCUA_PKI_OPENSSL_PASSIN"]);
        redacted.cwd.should.eql("/x");
        // and the original is untouched
        options.env.NODE_OPCUA_PKI_OPENSSL_PASSIN.should.eql("s3cret");
    });

    it("redactEnvForLog should leave options without env alone", () => {
        const options: { cwd: string; env?: NodeJS.ProcessEnv } = { cwd: "/y" };
        redactEnvForLog(options).should.eql({ cwd: "/y" });
    });
});
