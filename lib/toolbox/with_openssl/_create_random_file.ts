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
import path from "path";
import fs from "fs";
import { ErrorCallback } from "async";
import { g_config } from "../config";
import { ExecuteOptions, execute_openssl } from "./execute_openssl";
import { quote } from "../common";

const q = quote;

export function createRandomFile(randomFile: string, options: ExecuteOptions, callback: (err?: Error) => void) {
    // istanbul ignore next
    if (!useRandFile()) {
        return callback();
    }
    execute_openssl("rand " + " -out " + q(randomFile) + " -hex 256", options, (err: Error | null) => {
        callback(err ? err : undefined);
    });
}

export function createRandomFileIfNotExist(randomFile: string, options: ExecuteOptions, callback: ErrorCallback): void {
    const randomFilePath = options.cwd ? path.join(options.cwd, randomFile) : randomFile;
    if (fs.existsSync(randomFilePath)) {
        return callback();
    } else {
        createRandomFile(randomFile, options, callback);
    }
}

export function useRandFile() {
    // istanbul ignore next
    if (g_config.opensslVersion && g_config.opensslVersion.toLowerCase().indexOf("libressl") > -1) {
        return false;
    }
    return true;
}
