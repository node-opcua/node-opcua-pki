/* eslint-disable @typescript-eslint/no-explicit-any */
// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
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
// tslint:disable:no-console
// tslint:disable:no-shadowed-variable

import assert from "node:assert";
import child_process from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import byline from "byline";
import chalk from "chalk";
import { quote } from "../common";
import { makePath } from "../common2";
import { g_config } from "../config";
import { debugLog, displayError, doDebug, warningLog } from "../debug";
import { setEnv } from "./_env";
import { get_openssl_exec_path } from "./install_prerequisite";

// tslint:disable-next-line:variable-name

let opensslPath: string | undefined; // not initialized

const n = makePath;

export interface ExecuteOptions {
    cwd?: string;
    hideErrorMessage?: boolean;
}

export async function execute(cmd: string, options: ExecuteOptions): Promise<string> {
    const from = new Error();

    options.cwd = options.cwd || process.cwd();

    // istanbul ignore next
    if (!g_config.silent) {
        warningLog(chalk.cyan("                  CWD         "), options.cwd);
    }

    const outputs: string[] = [];

    return await new Promise((resolve, reject) => {
        const child = child_process.exec(
            cmd,
            {
                cwd: options.cwd,
                windowsHide: true
            },
            (err: child_process.ExecException | null) => {
                // istanbul ignore next
                if (err) {
                    if (!options.hideErrorMessage) {
                        const fence = "###########################################";
                        console.error(chalk.bgWhiteBright.redBright(`${fence} OPENSSL ERROR ${fence}`));
                        console.error(chalk.bgWhiteBright.redBright(`CWD = ${options.cwd}`));
                        console.error(chalk.bgWhiteBright.redBright(err.message));
                        console.error(chalk.bgWhiteBright.redBright(`${fence} OPENSSL ERROR ${fence}`));

                        console.error(from.stack);
                    }
                    reject(new Error(err.message));
                    return;
                }
                resolve(outputs.join(""));
            }
        );

        if (child.stdout) {
            const stream2 = byline(child.stdout);
            stream2.on("data", (line: string) => {
                outputs.push(`${line}\n`);
            });
            if (!g_config.silent) {
                stream2.on("data", (line: string) => {
                    line = line.toString();
                    if (doDebug) {
                        process.stdout.write(`${chalk.white("        stdout ") + chalk.whiteBright(line)}\n`);
                    }
                });
            }
        }

        // istanbul ignore next
        if (!g_config.silent) {
            if (child.stderr) {
                const stream1 = byline(child.stderr);
                stream1.on("data", (line: string) => {
                    line = line.toString();
                    if (displayError) {
                        process.stdout.write(`${chalk.white("        stderr ") + chalk.red(line)}\n`);
                    }
                });
            }
        }
    });
}

export async function find_openssl(): Promise<string> {
    return await get_openssl_exec_path();
}

export async function ensure_openssl_installed(): Promise<void> {
    if (!opensslPath) {
        opensslPath = await find_openssl();
        const outputs = await execute_openssl("version", { cwd: "." });
        g_config.opensslVersion = outputs.trim();
        if (doDebug) {
            warningLog("OpenSSL version : ", g_config.opensslVersion);
        }
    }
}

export async function executeOpensslAsync(cmd: string, options: ExecuteOpenSSLOptions): Promise<string> {
    return await execute_openssl(cmd, options);
}

export async function execute_openssl_no_failure(cmd: string, options: ExecuteOpenSSLOptions) {
    options = options || {};
    options.hideErrorMessage = true;
    try {
        return await execute_openssl(cmd, options);
    } catch (err) {
        debugLog(" (ignored error =  ERROR : )", (err as Error).message);
    }
}

function getTempFolder(): string {
    return os.tmpdir();
}

export interface ExecuteOpenSSLOptions extends ExecuteOptions {
    openssl_conf?: string;
}

export async function execute_openssl(cmd: string, options: ExecuteOpenSSLOptions): Promise<string> {
    debugLog("execute_openssl", cmd, options);
    const empty_config_file = n(getTempFolder(), "empty_config.cnf");
    if (!fs.existsSync(empty_config_file)) {
        await fs.promises.writeFile(empty_config_file, "# empty config file");
    }

    options = options || {};
    options.openssl_conf = options.openssl_conf || empty_config_file; // "!! OPEN SLL CONF NOT DEFINED BAD FILE !!";
    assert(options.openssl_conf);
    setEnv("OPENSSL_CONF", options.openssl_conf);

    // istanbul ignore next
    if (!g_config.silent) {
        warningLog(chalk.cyan("                  OPENSSL_CONF"), process.env.OPENSSL_CONF);
        warningLog(chalk.cyan("                  RANDFILE    "), process.env.RANDFILE);
        warningLog(chalk.cyan("                  CMD         openssl "), chalk.cyanBright(cmd));
    }
    await ensure_openssl_installed();
    return await execute(`${quote(opensslPath)} ${cmd}`, options);
}
