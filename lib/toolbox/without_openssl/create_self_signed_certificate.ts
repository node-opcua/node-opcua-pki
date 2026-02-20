// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2022-2024 Sterfive.com
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

import {
    Subject,
    CertificatePurpose,
    createSelfSignedCertificate as createSelfSignedCertificate1,
    pemToPrivateKey
} from "node-opcua-crypto";
import { adjustDate, type CreateSelfSignCertificateWithConfigParam } from "../common";
import { displayTitle } from "../display";

export async function createSelfSignedCertificateAsync(
    certificate: string,
    params: CreateSelfSignCertificateWithConfigParam
): Promise<void> {
    params.purpose = params.purpose || CertificatePurpose.ForApplication;
    assert(params.purpose, "Please provide a Certificate Purpose");
    /**
     * note: due to a limitation of openssl ,
     *       it is not possible to control the startDate of the certificate validity
     *       to achieve this the certificateAuthority tool shall be used.
     */
    assert(fs.existsSync(params.configFile));
    assert(fs.existsSync(params.rootDir));
    assert(fs.existsSync(params.privateKey));
    if (!params.subject) {
        throw Error("Missing subject");
    }

    assert(typeof params.applicationUri === "string");
    assert(Array.isArray(params.dns));

    // xx no key size in self-signed assert(params.keySize == 2048 || params.keySize == 4096);

    //            processAltNames(params);
    adjustDate(params);
    assert(Object.prototype.hasOwnProperty.call(params, "validity"));

    let subject: Subject | string = new Subject(params.subject);
    subject = subject.toString();

    // xx const certificateRequestFilename = certificate + ".csr";
    const purpose = params.purpose;

    displayTitle("Generate a certificate request");

    const privateKeyPem = await fs.promises.readFile(params.privateKey, "utf-8");
    const privateKey = await pemToPrivateKey(privateKeyPem);

    const { cert } = await createSelfSignedCertificate1({
        privateKey,
        notBefore: params.startDate,
        notAfter: params.endDate,
        validity: params.validity,
        dns: params.dns,
        ip: params.ip,
        subject,
        applicationUri: params.applicationUri,
        purpose
    });
    await fs.promises.writeFile(certificate, cert, "utf-8");
}

export async function createSelfSignedCertificate(
    certificate: string,
    params: CreateSelfSignCertificateWithConfigParam
): Promise<void> {
    await createSelfSignedCertificateAsync(certificate, params);
}
