/* eslint-disable @typescript-eslint/no-explicit-any */
// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2025 - Sterfive.com
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

import { Subject } from "../../misc/subject";
import { CreateCertificateSigningRequestWithConfigOptions, quote } from "../common";
import { makePath } from "../common2";
import { displaySubtitle } from "../display";
import { execute_openssl } from "./execute_openssl";
import { processAltNames } from "./_env";
import { generateStaticConfig } from "./toolbox";

const q = quote;
const n = makePath;

/**
 * create a certificate signing request
 */
export async function createCertificateSigningRequestWithOpenSSL(
    certificateSigningRequestFilename: string,
    params: CreateCertificateSigningRequestWithConfigOptions,
): Promise<void> {
    assert(params);
    assert(params.rootDir);
    assert(params.configFile);
    assert(params.privateKey);
    assert(typeof params.privateKey === "string");
    assert(fs.existsSync(params.configFile), "config file must exist " + params.configFile);
    assert(fs.existsSync(params.privateKey), "Private key must exist" + params.privateKey);
    assert(fs.existsSync(params.rootDir), "RootDir key must exist");
    assert(typeof certificateSigningRequestFilename === "string");

    // note : this openssl command requires a config file
    processAltNames(params);
    const configFile = generateStaticConfig(params.configFile, { cwd: params.rootDir});

    const options = { cwd: params.rootDir, openssl_conf: path.relative(params.rootDir,configFile) };

    const configOption = " -config " + q(n(configFile));

    const subject = params.subject ? new Subject(params.subject).toString() : undefined;
    // process.env.OPENSSL_CONF  ="";
    const subjectOptions = subject ? ' -subj "' + subject + '"' : "";

    displaySubtitle("- Creating a Certificate Signing Request with openssl");
    await execute_openssl(
        "req -new" +
            "  -sha256 " +
            " -batch " +
            " -text " +
            configOption +
            " -key " +
            q(n(params.privateKey)) +
            subjectOptions +
            " -out " +
            q(n(certificateSigningRequestFilename)),
        options,
    );
}
