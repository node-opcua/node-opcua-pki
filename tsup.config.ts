import { defineConfig } from "tsup";

export default defineConfig({
    entry: {
        "index": "lib/index.ts",
        "crypto_create_CA": "bin/crypto_create_CA.ts",
        "install_prerequisite": "bin/install_prerequisite.ts"
    },
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    target: "es2022",
    // minify: true,
    shims: true
});
