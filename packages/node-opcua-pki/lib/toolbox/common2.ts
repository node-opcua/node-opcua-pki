// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2026 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
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

/**
 * Restrict a file or directory to owner-only access (mode 0600/0700).
 *
 * fs.chmod only toggles the read-only attribute on Windows and cannot express
 * POSIX-style owner-only permissions, so this is a no-op there rather than a
 * false sense of protection. Errors are logged, not thrown: a read-only mount
 * or an unexpected ownership mismatch should not prevent the server from
 * starting.
 */
export function restrictPrivateFilePermissions(target: string, mode: 0o600 | 0o700): void {
    // istanbul ignore if
    if (process.platform === "win32") {
        return;
    }
    try {
        fs.chmodSync(target, mode);
    } catch (err) {
        // istanbul ignore next
        warningLog(chalk.yellow("        could not restrict permissions on "), target, (err as Error).message);
    }
}

/**
 * Create (or repair) a directory intended to hold private key material,
 * restricted to owner-only access. Safe to call on an existing directory
 * to repair permissions left by an earlier, less restrictive version.
 */
export function ensurePrivateDirectory(dir: string): void {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    restrictPrivateFilePermissions(dir, 0o700);
}

/**
 * `true` if the PEM file at `filename` holds a passphrase-encrypted PKCS#8
 * key (`-----BEGIN ENCRYPTED PRIVATE KEY-----`). Header check only; it does
 * not validate or decrypt the key. Throws if the file cannot be read.
 */
export function isEncryptedPrivateKeyFile(filename: string): boolean {
    return fs.readFileSync(filename, "utf-8").includes("-----BEGIN ENCRYPTED PRIVATE KEY-----");
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
