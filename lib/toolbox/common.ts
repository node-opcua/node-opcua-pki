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
    //     console.log(" start Date ", params.startDate.toUTCString(), x509Date(params.startDate));
    //     console.log(" end   Date ", params.endDate.toUTCString(), x509Date(params.endDate));
    // }
}

export function adjustApplicationUri(params: Params) {
    const applicationUri = params.applicationUri || "";
    if (applicationUri.length > 200) {
        throw new Error("Openssl doesn't support urn with length greater than 200" + applicationUri);
    }
}
