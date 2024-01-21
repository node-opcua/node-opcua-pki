/* eslint-disable @typescript-eslint/no-explicit-any */
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
// tslint:disable:no-console
// tslint:disable:no-shadowed-variable

import assert from "assert";

import byline from "byline";
import chalk from "chalk";
import child_process from "child_process";
import fs from "fs";
import os from "os";

import { get_openssl_exec_path } from "./install_prerequisite";
import {
    quote,
} from "../common";
import { g_config } from "../config";
import { debugLog, displayError, doDebug, warningLog } from "../debug";
import { setEnv } from "./_env";
import { make_path } from "../common2";

// tslint:disable-next-line:variable-name

let opensslPath: string | undefined; // not initialized

const n = make_path;


export interface ExecuteOptions {
    cwd?: string;
    hideErrorMessage?: boolean;
}

export function execute(cmd: string, options: ExecuteOptions, callback: Callback<string>) {
    assert(typeof callback === "function");

    const from = new Error();
    /// assert(g_config.CARootDir && fs.existsSync(option.CARootDir));
    options.cwd = options.cwd || process.cwd();

    // istanbul ignore next
    if (!g_config.silent) {
        warningLog(chalk.cyan("                  CWD         "), options.cwd);
    }

    const outputs: string[] = [];

    const child = child_process.exec(
        cmd,
        {
            cwd: options.cwd,
            windowsHide: true,
        },
        (err: child_process.ExecException | null) => {
            // istanbul ignore next
            if (err) {
                if (!options.hideErrorMessage) {
                    const fence = "###########################################";
                    console.error(chalk.bgWhiteBright.redBright(`${fence} OPENSSL ERROR ${fence}`));
                    console.error(chalk.bgWhiteBright.redBright("CWD = " + options.cwd));
                    console.error(chalk.bgWhiteBright.redBright(err.message));
                    console.error(chalk.bgWhiteBright.redBright(`${fence} OPENSSL ERROR ${fence}`));

                    console.error(from.stack);
                }
                callback(new Error(err.message));
                return;
            }
            callback(null, outputs.join(""));
        }
    );

    if (child.stdout) {
        const stream2 = byline(child.stdout);
        stream2.on("data", (line: string) => {
            outputs.push(line + "\n");
        });
        if (!g_config.silent) {
            stream2.on("data", (line: string) => {
                line = line.toString();
                if (doDebug) {
                    process.stdout.write(chalk.white("        stdout ") + chalk.whiteBright(line) + "\n");
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
                    process.stdout.write(chalk.white("        stderr ") + chalk.red(line) + "\n");
                }
            });
        }
    }
}

export function find_openssl(callback: (err: Error | null, opensslPath?: string) => void) {
    get_openssl_exec_path((err: Error | null, _opensslPath?: string) => {
        opensslPath = _opensslPath;
        callback(err, opensslPath);
    });
}

export function ensure_openssl_installed(callback: (err?: Error) => void) {
    assert(typeof callback === "function");
    if (!opensslPath) {
        return find_openssl((err: Error | null) => {
            // istanbul ignore next
            if (err) {
                return callback(err);
            }

            execute_openssl("version", { cwd: "." }, (err: Error | null, outputs?: string) => {
                // istanbul ignore next
                if (err || !outputs) {
                    return callback(err || new Error("no outputs"));
                }
                g_config.opensslVersion = outputs.trim();
                if (doDebug) {
                    warningLog("OpenSSL version : ", g_config.opensslVersion);
                }
                callback(err ? err : undefined);
            });
        });
    } else {
        return callback();
    }
}

export function executeOpensslAsync(cmd: string, options: ExecuteOpenSSLOptions): Promise<string> {
    return new Promise((resolve, reject) => {
        execute_openssl(cmd, options, (err, output) => {
            // istanbul ignore next
            if (err) {
                reject(err);
            } else {
                resolve(output || "");
            }
        });
    });
}

export function execute_openssl_no_failure(cmd: string, options: ExecuteOpenSSLOptions, callback: Callback<string>) {
    options = options || {};
    options.hideErrorMessage = true;
    execute_openssl(cmd, options, (err: Error | null, output?: string) => {
        // istanbul ignore next
        if (err) {
            debugLog(" (ignored error =  ERROR : )", err.message);
        }
        callback(null, output);
    });
}

function getTempFolder(): string {
    return os.tmpdir();
}

export interface ExecuteOpenSSLOptions extends ExecuteOptions {
    openssl_conf?: string;
}

type Callback<T> = (err: Error | null, output?: T) => void;
export function execute_openssl(cmd: string, options: ExecuteOpenSSLOptions, callback: Callback<string>): void {
    // tslint:disable-next-line:variable-name
    const empty_config_file = n(getTempFolder(), "empty_config.cnf");
    if (!fs.existsSync(empty_config_file)) {
        fs.writeFileSync(empty_config_file, "# empty config file");
    }

    assert(typeof callback === "function");

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

    ensure_openssl_installed((err?: Error) => {
        // istanbul ignore next
        if (err) {
            return callback(err);
        }
        execute(quote(opensslPath) + " " + cmd, options, callback);
    });
}
