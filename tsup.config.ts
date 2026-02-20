import { defineConfig } from "tsup";

export default defineConfig([
    {
        entry: {
            index: "lib/index.ts"
        },
        format: ["esm", "cjs"],
        dts: true,
        sourcemap: true,
        clean: true,
        target: "es2022",
        shims: true
    },
    {
        entry: {
            "bin/pki": "bin/pki.ts",
            "bin/install_prerequisite": "bin/install_prerequisite.ts"
        },
        format: ["esm"], // Only ESM for scripts
        dts: false,
        sourcemap: true,
        clean: false, // Don't wipe stage 1
        target: "es2022",
        shims: true,
        external: ["node-opcua-pki"]
    }
]);
