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

import { Subject } from "../../misc/subject";
import { ErrorCallback, quote } from "../common";
import {
    CreateSelfSignCertificateWithConfigParam,
    adjustDate,
} from "../common";
import { displayTitle } from "../display";
import { ensure_openssl_installed, execute_openssl } from "./execute_openssl";
import { generateStaticConfig,  } from "./toolbox";
import { processAltNames } from "./_env";

import { make_path } from "../common2";
import { CertificatePurpose } from "node-opcua-crypto";


const q = quote;
const n = make_path;

/**
 *
 * @param certificate
 * @param params
 * @param params.configFile
 * @param params.rootDir
 * @param params.privateKey
 * @param params.applicationUri
 * @param params.dns
 * @param params.ip
 * @param params.validity certificate duration in days
 * @param params.purpose
 * @param [params.subject= "C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=ZZNodeOPCUA"]
 * @param callback
 */
export function createSelfSignedCertificate(
    certificate: string,
    params: CreateSelfSignCertificateWithConfigParam,
    callback: (err?: Error | null) => void
) {
    ensure_openssl_installed((err) => {
        if (err) {
            return callback(err);
        }
        try {
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
                return callback(new Error("Missing subject"));
            }
            assert(typeof params.applicationUri === "string");
            assert(params.dns instanceof Array);

            // xx no key size in self-signed assert(params.keySize == 2048 || params.keySize == 4096);

            processAltNames(params);

            adjustDate(params);
            assert(Object.prototype.hasOwnProperty.call(params, "validity"));

            let subject: Subject | string = new Subject(params.subject);
            subject = subject.toString();

            const certificateRequestFilename = certificate + ".csr";

            const configFile = generateStaticConfig(params.configFile);
            const configOption = " -config " + q(n(configFile));

            let extension: string;
            switch (params.purpose) {
                case CertificatePurpose.ForApplication:
                    extension = "v3_selfsigned";
                    break;
                case CertificatePurpose.ForCertificateAuthority:
                    extension = "v3_ca";
                    break;
                case CertificatePurpose.ForUserAuthentication:
                default:
                    extension = "v3_selfsigned";
            }

            const tasks = [
                (callback: ErrorCallback) => {
                    displayTitle("Generate a certificate request", callback);
                },

                // Once the private key is generated a Certificate Signing Request can be generated.
                // The CSR is then used in one of two ways. Ideally, the CSR will be sent to a Certificate Authority, such as
                // Thawte or Verisign who will verify the identity of the requestor and issue a signed certificate.
                // The second option is to self-sign the CSR, which will be demonstrated in the next section
                (callback: ErrorCallback) => {
                    execute_openssl(
                        "req -new" +
                            " -sha256 " +
                            " -text " +
                            " -extensions " +
                            extension +
                            " " +
                            configOption +
                            " -key " +
                            q(n(params.privateKey)) +
                            " -out " +
                            q(n(certificateRequestFilename)) +
                            ' -subj "' +
                            subject +
                            '"',
                        {},
                        callback
                    );
                },

                // Xx // Step 3: Remove Passphrase from Key
                // Xx execute("cp private/cakey.pem private/cakey.pem.org");
                // Xx execute(openssl_path + " rsa -in private/cakey.pem.org
                // Xx -out private/cakey.pem -passin pass:"+paraphrase);

                (callback: ErrorCallback) => {
                    displayTitle("Generate Certificate (self-signed)", callback);
                },
                (callback: ErrorCallback) => {
                    execute_openssl(
                        " x509 -req " +
                            " -days " +
                            params.validity +
                            " -extensions " +
                            extension +
                            " " +
                            " -extfile " +
                            q(n(configFile)) +
                            " -in " +
                            q(n(certificateRequestFilename)) +
                            " -signkey " +
                            q(n(params.privateKey)) +
                            " -text " +
                            " -out " +
                            q(certificate) +
                            " -text ",
                        {},
                        callback
                    );
                },

                // remove unnecessary certificate request file
                (callback: ErrorCallback) => {
                    fs.unlink(certificateRequestFilename, callback);
                },
            ];
            async.series(tasks, callback);
        } catch (err) {
            callback(err as Error);
        }
    });
}
