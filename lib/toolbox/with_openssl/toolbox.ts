/* eslint-disable @typescript-eslint/no-explicit-any */
// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2024 - Sterfive.com
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
// tslint:disable:no-console
// tslint:disable:no-shadowed-variable

import assert from "assert";

import fs from "fs";
import path from "path";

import { Filename } from "../common";
import { quote } from "../common";
import { make_path } from "../common2";
import { g_config } from "../config";
import { ExecuteOptions, execute_openssl } from "./execute_openssl";
import { getEnvironmentVarNames, getEnv } from "./_env";

function openssl_require2DigitYearInDate() {
    // istanbul ignore next
    if (!g_config.opensslVersion) {
        throw new Error(
            "openssl_require2DigitYearInDate : openssl version is not known:" + "  please call ensure_openssl_installed()",
        );
    }
    return g_config.opensslVersion.match(/OpenSSL 0\.9/);
}

g_config.opensslVersion = "";

export function generateStaticConfig(configPath: string, options?: ExecuteOptions) {
    const prePath = (options && options.cwd) || "";
    const staticConfigPath = configPath + ".tmp";
    let staticConfig = fs.readFileSync(path.join(prePath, configPath), { encoding: "utf8" });
    for (const envVar of getEnvironmentVarNames()) {
        staticConfig = staticConfig.replace(new RegExp(envVar.pattern, "gi"), getEnv(envVar.key));
    }
    fs.writeFileSync(path.join(prePath, staticConfigPath), staticConfig);

    return staticConfigPath;
}

const q = quote;
const n = make_path;

/**
 *   calculate the public key from private key
 *   openssl rsa -pubout -in private_key.pem
 *
 * @method getPublicKeyFromPrivateKey
 * @param privateKeyFilename: the existing file with the private key
 * @param publicKeyFilename: the file where to store the public key
 */
export async function getPublicKeyFromPrivateKey(privateKeyFilename: string, publicKeyFilename: string): Promise<void> {
    assert(fs.existsSync(privateKeyFilename));
    await execute_openssl("rsa -pubout -in " + q(n(privateKeyFilename)) + " -out " + q(n(publicKeyFilename)), {});
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
    await execute_openssl("x509 -pubkey -in " + q(n(certificateFilename)) + " > " + q(n(publicKeyFilename)), {});
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
        return ("" + s).padStart(l, "0");
    }

    if (openssl_require2DigitYearInDate()) {
        // for example: on MacOS , where openssl 0.98 is installed by default
        return w(Y, 2) + w(M, 2) + w(D, 2) + w(h, 2) + w(m, 2) + w(s, 2) + "Z";
    } else {
        // for instance when openssl version is greater than 1.0.0
        return w(Y, 4) + w(M, 2) + w(D, 2) + w(h, 2) + w(m, 2) + w(s, 2) + "Z";
    }
}

/**
 * @param certificate - the certificate file in PEM format, file must exist
 */
export async function dumpCertificate(certificate: Filename): Promise<string> {
    assert(fs.existsSync(certificate));
    return await execute_openssl("x509 " + " -in " + q(n(certificate)) + " -text " + " -noout", {});
}

export async function toDer(certificatePem: string): Promise<string> {
    assert(fs.existsSync(certificatePem));
    const certificateDer = certificatePem.replace(".pem", ".der");
    return await execute_openssl("x509  " + " -outform der " + " -in " + certificatePem + " -out " + certificateDer, {});
}

export async function fingerprint(certificatePem: string): Promise<string> {
    // openssl x509 -in my_certificate.pem -hash -dates -noout -fingerprint
    assert(fs.existsSync(certificatePem));
    return await execute_openssl("x509  " + " -fingerprint " + " -noout " + " -in " + certificatePem, {});
}
