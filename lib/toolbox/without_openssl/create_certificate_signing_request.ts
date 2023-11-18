// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2022-2023 Sterfive.com
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
import assert from "assert";
import fs from "fs";
import { CreateCertificateSigningRequestWithConfigOptions } from "../common";
import { Subject, pemToPrivateKey } from "node-opcua-crypto";
import { display, displaySubtitle } from "../display";
import { createCertificateSigningRequest as createCertificateSigningRequest1 } from "node-opcua-crypto";
/**
 * create a certificate signing request
 *
 * @param certificateSigningRequestFilename
 * @param params
 * @param callback
 */
export async function createCertificateSigningRequestAsync(
    certificateSigningRequestFilename: string,
    params: CreateCertificateSigningRequestWithConfigOptions
): Promise<void> {
    assert(params);
    assert(params.rootDir);
    assert(params.configFile);
    assert(params.privateKey);
    assert(typeof params.privateKey === "string");
    assert(fs.existsSync(params.privateKey), "Private key must exist" + params.privateKey);

    //  assert(fs.existsSync(params.configFile), "config file must exist " + params.configFile);
    assert(fs.existsSync(params.rootDir), "RootDir key must exist");
    assert(typeof certificateSigningRequestFilename === "string");

    const subject = params.subject ? new Subject(params.subject).toString() : undefined;
    displaySubtitle("- Creating a Certificate Signing Request with subtile");

    const privateKeyPem = await fs.promises.readFile(params.privateKey, "utf-8");
    const privateKey = await pemToPrivateKey(privateKeyPem);

    const { csr } = await createCertificateSigningRequest1({
        privateKey,
        dns: params.dns,
        ip: params.ip,
        subject,
        applicationUri: params.applicationUri,
        purpose: params.purpose,
    });
    await fs.promises.writeFile(certificateSigningRequestFilename, csr, "utf-8");

    display("- privateKey " + params.privateKey);
    display("- certificateSigningRequestFilename " + certificateSigningRequestFilename);

    // to verify that the CSR is correct: 
    // openssl  req -in ./tmp/without_openssl.csr -noout -verify
}

export function createCertificateSigningRequest(
    certificateSigningRequestFilename: string,
    params: CreateCertificateSigningRequestWithConfigOptions,
    callback: (err?: Error) => void
): void {
    createCertificateSigningRequestAsync(certificateSigningRequestFilename, params)
        .then(() => callback())
        .catch((err) => callback(err));
}
