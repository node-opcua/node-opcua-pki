// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2026 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so,  subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------
import type { ProcessAltNamesParam } from "../common";
import { g_config } from "../config";
import { warningLog } from "../debug";

/**
 * Environment variables passed through to every openssl child process,
 * beyond whatever a specific call explicitly needs (e.g. a passphrase via
 * `ExecuteOptions.env`).
 *
 * This app's own config-templating (ALTNAME, CDP_URL, AIA_VALUE — see
 * `generateStaticConfig`) substitutes values directly into the config file
 * content; it never relies on the openssl child actually seeing those as
 * real OS environment variables. Only `OPENSSL_CONF` and `RANDFILE` are
 * genuinely required at the OS level, alongside whatever the shell, the
 * dynamic loader, and the openssl binary themselves need to start up on
 * each platform.
 *
 * Rather than handing the child the full parent process environment —
 * which, in a hosting application, may hold unrelated secrets (API keys,
 * database credentials, tokens) that have no business being visible to a
 * spawned openssl process — only this curated, minimal set is passed
 * through. The same set is used to *discover* the openssl binary
 * (`install_prerequisite`) and to *run* it, so a binary that is found is
 * also one that can start.
 */
export const SAFE_ENV_PASSTHROUGH: ReadonlySet<string> = new Set([
    // POSIX/Windows shell and process essentials
    "path",
    "home",
    "userprofile",
    "temp",
    "tmp",
    "tmpdir",
    "systemroot",
    "windir",
    "comspec",
    "pathext",
    "appdata",
    "localappdata",
    // dynamic loader: a custom-built or relocated openssl (e.g. under /opt,
    // or Homebrew on macOS) may need these to find its own libcrypto/libssl
    "ld_library_path",
    "dyld_library_path",
    "dyld_fallback_library_path",
    // locale, so openssl's textual output stays parseable
    "lang",
    "lc_all",
    "lc_ctype",
    // openssl configuration this app, or the host OS/user, may rely on
    "openssl_conf",
    "randfile",
    "openssl_modules",
    "openssl_engines",
    "ssl_cert_file",
    "ssl_cert_dir"
]);

/**
 * Build the environment for an openssl child process: the allowlisted
 * subset of `process.env` (see {@link SAFE_ENV_PASSTHROUGH}), overlaid with
 * `extra` (per-invocation values such as a passphrase for `-passin env:`).
 * Never writes to `process.env`.
 */
export function buildChildEnv(extra?: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {};
    for (const key of Object.keys(process.env)) {
        if (SAFE_ENV_PASSTHROUGH.has(key.toLowerCase())) {
            env[key] = process.env[key];
        }
    }
    return { ...env, ...extra };
}

/**
 * A copy of `options` safe to hand to a logger: the values of any
 * per-invocation `env` are replaced by their variable names, so a passphrase
 * passed for `-passin env:NAME` can never end up in debug output.
 */
export function redactEnvForLog<T extends { env?: NodeJS.ProcessEnv }>(options: T): Omit<T, "env"> & { env?: string[] } {
    const { env, ...rest } = options;
    return env ? { ...rest, env: Object.keys(env) } : rest;
}

export const exportedEnvVars: Record<string, string> = {};

export function setEnv(varName: string, value: string): void {
    // istanbul ignore next
    if (!g_config.silent) {
        warningLog(`          set ${varName}=${value}`);
    }
    exportedEnvVars[varName] = value;

    if (["OPENSSL_CONF"].indexOf(varName) >= 0) {
        process.env[varName] = value;
    }
    if (["RANDFILE"].indexOf(varName) >= 0) {
        process.env[varName] = value;
    }
}

export function hasEnv(varName: string): boolean {
    return Object.prototype.hasOwnProperty.call(exportedEnvVars, varName);
}
export function getEnv(varName: string): string {
    return exportedEnvVars[varName];
}

export function unsetEnv(varName: string): void {
    delete exportedEnvVars[varName];
}

export function getEnvironmentVarNames(): { key: string; pattern: string }[] {
    return Object.keys(exportedEnvVars).map((varName: string) => {
        return { key: varName, pattern: `\\$ENV\\:\\:${varName}` };
    });
}

export function processAltNames(params: ProcessAltNamesParam) {
    params.dns = params.dns || [];
    params.ip = params.ip || [];

    // construct subjectAtlName
    let subjectAltName: string[] = [];
    subjectAltName.push(`URI:${params.applicationUri}`);
    subjectAltName = ([] as string[]).concat(
        subjectAltName,
        params.dns.map((d: string) => `DNS:${d}`)
    );
    subjectAltName = ([] as string[]).concat(
        subjectAltName,
        params.ip.map((d: string) => `IP:${d}`)
    );
    const subjectAltNameString = subjectAltName.join(", ");
    setEnv("ALTNAME", subjectAltNameString);
}
