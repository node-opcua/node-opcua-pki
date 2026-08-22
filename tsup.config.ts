import { defineConfig } from "tsup";

const pkgDir = "packages/node-opcua-pki";

// Read the inner package.json to get runtime deps as externals
const innerPkg = require(`./${pkgDir}/package.json`);
const externalDeps = Object.keys(innerPkg.dependencies || {});

export default defineConfig([
    {
        entry: {
            index: `${pkgDir}/lib/index.ts`,
            // built separately, not split out of index: a single pre-bundled
            // file is not reliably tree-shakeable, so the openssl-free entry
            // has to be its own output to actually be openssl-free
            core: `${pkgDir}/lib/core.ts`
        },
        outDir: `${pkgDir}/dist`,
        format: ["esm", "cjs"],
        dts: true,
        sourcemap: true,
        clean: true,
        target: "es2022",
        shims: true,
        external: externalDeps
    },
    {
        entry: {
            "bin/pki": `${pkgDir}/bin/pki.ts`,
            "bin/install_prerequisite": `${pkgDir}/bin/install_prerequisite.ts`
        },
        outDir: `${pkgDir}/dist`,
        format: ["esm"], // Only ESM for scripts
        dts: false,
        sourcemap: true,
        clean: false, // Don't wipe stage 1
        target: "es2022",
        shims: true,
        external: [...externalDeps, "node-opcua-pki"]
    }
]);
