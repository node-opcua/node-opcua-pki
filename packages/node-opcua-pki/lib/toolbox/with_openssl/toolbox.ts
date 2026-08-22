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

import assert from "node:assert";

import fs from "node:fs";
import path from "node:path";

import type { Filename } from "../common";
import { makePath } from "../common2";
import { g_config } from "../config";
import { getEnv, getEnvironmentVarNames, hasEnv } from "./_env";
import { type ExecuteOptions, execute_openssl, passinArg } from "./execute_openssl";

function openssl_require2DigitYearInDate() {
    // istanbul ignore next
    if (!g_config.opensslVersion) {
        throw new Error(
            "openssl_require2DigitYearInDate : openssl version is not known:" + "  please call ensure_openssl_installed()"
        );
    }
    return g_config.opensslVersion.match(/OpenSSL 0\.9/);
}

g_config.opensslVersion = "";

let _counter = 0;

/**
 * Strip Mustache-style conditional blocks from an OpenSSL config template.
 *
 *   {{#KEY}}...{{/KEY}}
 *
 * The block content is **kept** (markers removed) iff `KEY` resolves to a
 * non-empty value — from `envOverrides` if it names the key, otherwise from
 * the global registry (see {@link exportedEnvVars}) — and stripped
 * (including the markers and the trailing newline) otherwise.
 *
 * Used to drive opt-in extensions like CRL Distribution Points and
 * Authority Information Access: the same template serves the
 * extension-set case (URL configured) and the extension-omitted case
 * (no URL configured).
 */
function stripConditionalBlocks(template: string, envOverrides?: Readonly<Record<string, string>>): string {
    return template.replace(/\{\{#([A-Z_][A-Z0-9_]*)\}\}([\s\S]*?)\{\{\/\1\}\}\r?\n?/g, (_match, key: string, content: string) => {
        const keep =
            envOverrides && Object.prototype.hasOwnProperty.call(envOverrides, key)
                ? envOverrides[key] !== ""
                : hasEnv(key) && getEnv(key) !== "";
        return keep ? content : "";
    });
}

/**
 * Render an OpenSSL config template (`$ENV::NAME` substitution, `{{#NAME}}`
 * conditional blocks) to a temporary file and return its path.
 *
 * `envOverrides`, when given, is consulted before the global env registry
 * for every key it names — the substituted value never depends on whatever
 * `setEnv()` calls other, possibly-concurrent code made before or after this
 * call. Pass it for any value the caller has already computed locally (as
 * every `CertificateAuthority` operation now does for `ALTNAME` /
 * `CDP_URL` / `AIA_VALUE`); omit it, as every other caller does, to keep
 * reading the shared registry exactly as before.
 */
export function generateStaticConfig(
    configPath: string,
    options?: ExecuteOptions,
    envOverrides?: Readonly<Record<string, string>>
) {
    const prePath = options?.cwd || "";

    const originalFilename = !path.isAbsolute(configPath) ? path.join(prePath, configPath) : configPath;
    let staticConfig = fs.readFileSync(originalFilename, { encoding: "utf8" });
    // Strip conditional blocks first so unset placeholders never reach
    // the env-var substitution pass below.
    staticConfig = stripConditionalBlocks(staticConfig, envOverrides);
    // Substituted values go through the function form of String.replace: the
    // string form interprets `$`-sequences (`$&`, `$$`, "$`", `$'`) in the
    // VALUE as replacement patterns, so a subject CN or CDP/OCSP URL
    // containing `$&` would re-insert the `$ENV::NAME` literal into the
    // rendered config and every openssl call on it would fail with
    // "variable has no value".
    for (const envVar of getEnvironmentVarNames()) {
        if (envOverrides && Object.prototype.hasOwnProperty.call(envOverrides, envVar.key)) {
            continue; // overridden below
        }
        staticConfig = staticConfig.replace(new RegExp(envVar.pattern, "gi"), () => getEnv(envVar.key));
    }
    if (envOverrides) {
        for (const [key, value] of Object.entries(envOverrides)) {
            staticConfig = staticConfig.replace(new RegExp(`\\$ENV\\:\\:${key}`, "gi"), () => value);
        }
    }
    const staticConfigPath = `${configPath}.${process.pid}-${_counter++}.tmp`;
    const temporaryConfigPath = !path.isAbsolute(configPath) ? path.join(prePath, staticConfigPath) : staticConfigPath;
    fs.writeFileSync(temporaryConfigPath, staticConfig);
    if (options?.cwd) {
        return path.relative(options.cwd, temporaryConfigPath);
    } else {
        return temporaryConfigPath;
    }
}

/**
 * Remove a rendered temp config produced by {@link generateStaticConfig}.
 * `configFile` is whatever that function returned (relative to
 * `options.cwd` when a cwd was given, absolute otherwise). Every caller of
 * `generateStaticConfig` is expected to pair it with this in a `finally`,
 * or the `<name>.<pid>-<n>.tmp` files accumulate next to the real config
 * forever.
 */
export async function cleanupStaticConfig(configFile: string, options?: ExecuteOptions): Promise<void> {
    await fs.promises.rm(path.resolve(options?.cwd ?? "", configFile), { force: true });
}

const n = makePath;

/**
 *   calculate the public key from private key
 *   openssl rsa -pubout -in private_key.pem -passin env:...
 *
 * `-passin` is always emitted (empty for a plaintext key) so an encrypted
 * key without a passphrase fails fast instead of hanging on a TTY prompt.
 *
 * @method getPublicKeyFromPrivateKey
 * @param privateKeyFilename: the existing file with the private key
 * @param publicKeyFilename: the file where to store the public key
 * @param passphrase: decrypts `privateKeyFilename` if it is an encrypted PKCS#8 key
 */
export async function getPublicKeyFromPrivateKey(
    privateKeyFilename: string,
    publicKeyFilename: string,
    passphrase?: string
): Promise<void> {
    assert(fs.existsSync(privateKeyFilename));
    const passin = passinArg(passphrase);
    await execute_openssl(["rsa", "-pubout", "-in", n(privateKeyFilename), "-out", n(publicKeyFilename), ...passin.args], {
        env: passin.env
    });
}

/**
 * extract public key from a certificate
 *   openssl x509 -pubkey -in certificate.pem -nottext
 *
 * @method getPublicKeyFromCertificate
 * @param certificateFilename
 * @param publicKeyFilename
 */
export async function getPublicKeyFromCertificate(certificateFilename: string, publicKeyFilename: string) {
    assert(fs.existsSync(certificateFilename));
    // no shell, so no `>` redirection: capture stdout and write it ourselves
    const output = await execute_openssl(["x509", "-pubkey", "-in", n(certificateFilename)], {});
    await fs.promises.writeFile(publicKeyFilename, output);
}
export function x509Date(date?: Date): string {
    date = date || new Date();
    const Y = date.getUTCFullYear();
    const M = date.getUTCMonth() + 1;
    const D = date.getUTCDate();
    const h = date.getUTCHours();
    const m = date.getUTCMinutes();
    const s = date.getUTCSeconds();

    function w(s: string | number, l: number): string {
        return `${s}`.padStart(l, "0");
    }

    if (openssl_require2DigitYearInDate()) {
        // for example: on MacOS , where openssl 0.98 is installed by default
        return `${w(Y, 2) + w(M, 2) + w(D, 2) + w(h, 2) + w(m, 2) + w(s, 2)}Z`;
    } else {
        // for instance when openssl version is greater than 1.0.0
        return `${w(Y, 4) + w(M, 2) + w(D, 2) + w(h, 2) + w(m, 2) + w(s, 2)}Z`;
    }
}

/**
 * @param certificate - the certificate file in PEM format, file must exist
 */
export async function dumpCertificate(certificate: Filename): Promise<string> {
    assert(fs.existsSync(certificate));
    return await execute_openssl(["x509", "-in", n(certificate), "-text", "-noout"], {});
}

export async function toDer(certificatePem: string): Promise<string> {
    assert(fs.existsSync(certificatePem));
    const certificateDer = certificatePem.replace(".pem", ".der");
    return await execute_openssl(["x509", "-outform", "der", "-in", certificatePem, "-out", certificateDer], {});
}

export async function fingerprint(certificatePem: string): Promise<string> {
    // openssl x509 -in my_certificate.pem -hash -dates -noout -fingerprint
    assert(fs.existsSync(certificatePem));
    return await execute_openssl(["x509", "-fingerprint", "-noout", "-in", certificatePem], {});
}
