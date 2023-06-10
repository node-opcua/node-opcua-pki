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
import assert = require("assert");

export type KeySize = 1024 | 2048 | 3072 | 4096;
export type Thumbprint = string;
export type Filename = string;
export type CertificateStatus = "unknown" | "trusted" | "rejected";
export type ErrorCallback = (err?: Error | null) => void;

import { SubjectOptions } from "../misc/subject";
import { CertificatePurpose } from "node-opcua-crypto";

export type KeyLength = 1024 | 2048 | 3072 | 4096;

export function quote(str?: string): string {
    return '"' + (str || "") + '"';
}

export interface ProcessAltNamesParam {
    dns?: string[];
    ip?: string[];
    applicationUri?: string;
}

// tslint:disable-next:no-empty-interface
export interface CreateCertificateSigningRequestOptions extends ProcessAltNamesParam {
    subject?: SubjectOptions | string;
}

export interface CreateCertificateSigningRequestWithConfigOptions extends CreateCertificateSigningRequestOptions {
    rootDir: Filename;
    configFile: Filename;
    privateKey: Filename;
    purpose: CertificatePurpose;
}

export interface StartDateEndDateParam {
    startDate?: Date;
    endDate?: Date;
    validity?: number;
}

export interface CreateSelfSignCertificateParam extends ProcessAltNamesParam, StartDateEndDateParam {
    subject?: SubjectOptions | string;
}

// purpose of self-signed certificate

export interface CreateSelfSignCertificateWithConfigParam extends CreateSelfSignCertificateParam {
    rootDir: Filename;
    configFile: Filename;
    privateKey: Filename;
    purpose: CertificatePurpose;
}

export interface Params extends ProcessAltNamesParam, StartDateEndDateParam {
    subject?: SubjectOptions | string;

    privateKey?: string;
    configFile?: string;
    rootDir?: string;

    outputFile?: string;
    reason?: string;
}

export function adjustDate(params: StartDateEndDateParam) {
    assert(params instanceof Object);
    params.startDate = params.startDate || new Date();
    assert(params.startDate instanceof Date);

    params.validity = params.validity || 365; // one year

    params.endDate = new Date(params.startDate.getTime());
    params.endDate.setDate(params.startDate.getDate() + params.validity);

    // params.endDate = x509Date(endDate);
    // params.startDate = x509Date(startDate);

    assert(params.endDate instanceof Date);
    assert(params.startDate instanceof Date);

    // // istanbul ignore next
    // if (!g_config.silent) {
    //     warningLog(" start Date ", params.startDate.toUTCString(), x509Date(params.startDate));
    //     warningLog(" end   Date ", params.endDate.toUTCString(), x509Date(params.endDate));
    // }
}

export function adjustApplicationUri(params: Params) {
    const applicationUri = params.applicationUri || "";
    if (applicationUri.length > 200) {
        throw new Error("Openssl doesn't support urn with length greater than 200" + applicationUri);
    }
}
