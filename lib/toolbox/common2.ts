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

import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";

import chalk from "chalk";

import { g_config } from "./config";

import { debugLog, warningLog } from "./debug";

export function certificateFileExist(certificateFile: string): boolean {
    // istanbul ignore next
    if (fs.existsSync(certificateFile) && !g_config.force) {
        warningLog(
            chalk.yellow("        certificate ") + chalk.cyan(certificateFile) + chalk.yellow(" already exists => do not overwrite")
        );
        return false;
    }
    return true;
}

export function mkdirRecursiveSync(folder: string): void {
    if (!fs.existsSync(folder)) {
        // istanbul ignore next
        debugLog(chalk.white(" .. constructing "), folder);
        fs.mkdirSync(folder, { recursive: true });
    }
}

export function makePath(folderName: string, filename?: string): string {
    let s: string;
    if (filename) {
        s = path.join(path.normalize(folderName), filename);
    } else {
        assert(folderName);
        s = folderName;
    }
    s = s.replace(/\\/g, "/");
    return s;
}
