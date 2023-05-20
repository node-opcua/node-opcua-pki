/* eslint-disable @typescript-eslint/no-explicit-any */
// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2023 - Sterfive.com
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

import * as assert from "assert";

import * as async from "async";
import * as fs from "fs";
import * as path from "path";

import { Subject } from "../../misc/subject";
import { Filename } from "../common";
import {
    CreateCertificateSigningRequestWithConfigOptions,
    ProcessAltNamesParam,
    quote,
} from "../common";
import { make_path } from "../common2";
import { g_config } from "../config";
import { displaySubtitle } from "../display";
import { ExecuteOptions, execute_openssl } from "./execute_openssl";
import { getEnvironmentVarNames, getEnv, setEnv} from "./_env";



function openssl_require2DigitYearInDate() {
    // istanbul ignore next
    if (!g_config.opensslVersion) {
        throw new Error(
            "openssl_require2DigitYearInDate : openssl version is not known:" + "  please call ensure_openssl_installed(callback)"
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
 * @param privateKeyFilename
 * @param publicKeyFilename
 * @param callback
 */
export function getPublicKeyFromPrivateKey(
    privateKeyFilename: string,
    publicKeyFilename: string,
    callback: (err: Error | null) => void
) {
    assert(fs.existsSync(privateKeyFilename));
    execute_openssl("rsa -pubout -in " + q(n(privateKeyFilename)) + " -out " + q(n(publicKeyFilename)), {}, callback);
}

/**
 * extract public key from a certificate
 *   openssl x509 -pubkey -in certificate.pem -nottext
 *
 * @method getPublicKeyFromCertificate
 * @param certificateFilename
 * @param publicKeyFilename
 * @param callback
 */
export function getPublicKeyFromCertificate(
    certificateFilename: string,
    publicKeyFilename: string,
    callback: (err: Error | null) => void
) {
    assert(fs.existsSync(certificateFilename));
    execute_openssl("x509 -pubkey -in " + q(n(certificateFilename)) + " > " + q(n(publicKeyFilename)), {}, callback);
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
 * @param callback
 */
export function dumpCertificate(certificate: Filename, callback: (err: Error | null, output?: string) => void): void {
    assert(fs.existsSync(certificate));
    assert(typeof callback === "function");

    execute_openssl("x509 " + " -in " + q(n(certificate)) + " -text " + " -noout", {}, callback);
}

export function toDer(certificatePem: string, callback: (err: Error | null, output?: string) => void) {
    assert(fs.existsSync(certificatePem));
    const certificateDer = certificatePem.replace(".pem", ".der");
    execute_openssl("x509  " + " -outform der " + " -in " + certificatePem + " -out " + certificateDer, {}, callback);
}

export function fingerprint(certificatePem: string, callback: (err: Error | null, output?: string) => void) {
    // openssl x509 -in my_certificate.pem -hash -dates -noout -fingerprint
    assert(fs.existsSync(certificatePem));
    execute_openssl("x509  " + " -fingerprint " + " -noout " + " -in " + certificatePem, {}, callback);
}
