import { defineConfig } from "tsup";

const pkgDir = "packages/node-opcua-pki";

// Read the inner package.json to get runtime deps as externals
const innerPkg = require(`./${pkgDir}/package.json`);
const externalDeps = Object.keys(innerPkg.dependencies || {});

export default defineConfig([
    {
        entry: {
            index: `${pkgDir}/lib/index.ts`
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
