// ---------------------------------------------------------------------------------------------------------------------
// node-opcua
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
import { ProcessAltNamesParam } from "../common";
import { g_config } from "../config";

export const exportedEnvVars: any = {};

export function setEnv(varName: string, value: string): void {
    // istanbul ignore next
    if (!g_config.silent) {
        console.log("          set " + varName + "=" + value);
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

export function getEnvironmentVarNames(): any[] {
    return Object.keys(exportedEnvVars).map((varName: string) => {
        return { key: varName, pattern: "\\$ENV\\:\\:" + varName };
    });
}


export function processAltNames(params: ProcessAltNamesParam) {
    params.dns = params.dns || [];
    params.ip = params.ip || [];

    // construct subjectAtlName
    let subjectAltName: string[] = [];
    subjectAltName.push("URI:" + params.applicationUri);
    subjectAltName = ([] as string[]).concat(
        subjectAltName,
        params.dns.map((d: string) => "DNS:" + d)
    );
    subjectAltName = ([] as string[]).concat(
        subjectAltName,
        params.ip.map((d: string) => "IP:" + d)
    );
    const subjectAltNameString = subjectAltName.join(", ");
    setEnv("ALTNAME", subjectAltNameString);
}

