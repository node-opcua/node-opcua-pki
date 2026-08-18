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
import child_process from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import byline from "byline";
import chalk from "chalk";
import { quote } from "../common";
import { makePath } from "../common2";
import { g_config } from "../config";
import { debugLog, displayError, doDebug, warningLog } from "../debug";
import { buildChildEnv, redactEnvForLog, setEnv } from "./_env";
import { get_openssl_exec_path } from "./install_prerequisite";

let opensslPath: string | undefined; // not initialized

const n = makePath;

export interface ExecuteOptions {
    cwd?: string;
    hideErrorMessage?: boolean;
    /**
     * Extra environment variables for this invocation only. Merged with a
     * curated, minimal passthrough of the current process environment (see
     * `SAFE_ENV_PASSTHROUGH` in `_env.ts`) for the spawned child — never the full parent
     * environment, and never written to `process.env`, so concurrent
     * invocations cannot see or clobber each other's values and unrelated
     * secrets sitting in the host application's environment are never handed
     * to the openssl child.
     *
     * Use this together with openssl's `-passin env:NAME` / `-passout
     * env:NAME` syntax to pass a secret without ever placing it in the
     * command string: a value embedded in the command string is both
     * visible to other processes via the process list and, because `execute`
     * runs the command through a shell, vulnerable to shell-metacharacter
     * injection if the secret is attacker-influenced. Passing it via a
     * dedicated environment variable avoids both.
     */
    env?: NodeJS.ProcessEnv;
}

// Fixed names for the per-invocation environment variables used to pass
// passphrases to openssl via `-passin env:NAME` / `-passout env:NAME`
// instead of interpolating them into the shell command string (see
// ExecuteOptions.env for why). Safe to reuse across concurrent calls: each
// call passes its own `env` object to a distinct child_process.exec
// invocation — nothing here touches process.env, so there is no shared
// mutable state to race on.
const PASSIN_ENV_VAR = "NODE_OPCUA_PKI_OPENSSL_PASSIN";
const PASSOUT_ENV_VAR = "NODE_OPCUA_PKI_OPENSSL_PASSOUT";

/** An openssl argument fragment plus the env it needs; merge `env` into `ExecuteOptions.env`. */
export interface OpensslPassArg {
    cmd: string;
    env: NodeJS.ProcessEnv;
}

/**
 * `-passin env:...` for a source passphrase (an input key or PFX bundle).
 *
 * Always emit this — with `""` when there is no passphrase — for any command
 * that reads a private key which *might* be encrypted: without a `-passin`,
 * openssl prompts on the controlling terminal for an encrypted key, and a
 * headless `child_process.exec` (no timeout, no TTY) then hangs forever. An
 * empty `-passin` on a plaintext key is a no-op; on an encrypted key it
 * fails fast with `bad decrypt` instead.
 */
export function passinArg(passphrase = ""): OpensslPassArg {
    return { cmd: `-passin env:${PASSIN_ENV_VAR}`, env: { [PASSIN_ENV_VAR]: passphrase } };
}

/** `-passout env:...` for an output passphrase (a PFX bundle being written). */
export function passoutArg(passphrase = ""): OpensslPassArg {
    return { cmd: `-passout env:${PASSOUT_ENV_VAR}`, env: { [PASSOUT_ENV_VAR]: passphrase } };
}

export async function execute(cmd: string, options: ExecuteOptions): Promise<string> {
    const from = new Error();

    options.cwd = options.cwd || process.cwd();

    // istanbul ignore next
    if (!g_config.silent) {
        warningLog(chalk.cyan("                  CWD         "), options.cwd);
    }

    const outputs: string[] = [];
    const errorOutputs: string[] = [];

    return await new Promise((resolve, reject) => {
        // `spawn` with `shell: true` is exactly what `exec` does underneath
        // (same command-string semantics on every platform), but lets us set
        // stdin to 'ignore' (/dev/null) instead of the pipe/socket `exec`
        // gives the child. That matters for any command that reads a
        // passphrase-protected key: OpenSSL's app UI layer opens the
        // console *before* honouring `-passin`, and with no controlling TTY
        // it falls back to stdin and calls tcgetattr on it. On a socket
        // that yields ENOTTY on Linux (tolerated) but EOPNOTSUPP on macOS
        // (not tolerated: "UI routines:open_console:unknown ttyget errno
        // value") and the key load fails even though the passphrase was
        // supplied. /dev/null yields ENOTTY everywhere. It also removes any
        // way for openssl to block reading a password from stdin.
        const child = child_process.spawn(cmd, {
            shell: true,
            cwd: options.cwd,
            windowsHide: true,
            env: buildChildEnv(options.env),
            stdio: ["ignore", "pipe", "pipe"]
        });

        const fail = (message: string) => {
            // istanbul ignore next
            if (!options.hideErrorMessage) {
                const fence = "###########################################";
                console.error(chalk.bgWhiteBright.redBright(`${fence} OPENSSL ERROR ${fence}`));
                console.error(chalk.bgWhiteBright.redBright(`CWD = ${options.cwd}`));
                console.error(chalk.bgWhiteBright.redBright(message));
                console.error(chalk.bgWhiteBright.redBright(`${fence} OPENSSL ERROR ${fence}`));

                console.error(from.stack);
            }
            reject(new Error(message));
        };

        child.on("error", (err: Error) => fail(`Command failed: ${cmd}\n${err.message}`));
        child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
            if (code === 0) {
                resolve(outputs.join(""));
                return;
            }
            // same message shape as child_process.exec: command, then stderr
            const why = signal ? `signal ${signal}` : `exit code ${code}`;
            fail(`Command failed: ${cmd}\n${errorOutputs.join("")}(${why})`);
        });

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

        if (child.stderr) {
            const stream1 = byline(child.stderr);
            stream1.on("data", (line: string) => {
                line = line.toString();
                errorOutputs.push(`${line}\n`);
                // istanbul ignore next
                if (!g_config.silent && displayError) {
                    process.stdout.write(`${chalk.white("        stderr ") + chalk.red(line)}\n`);
                }
            });
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
    // never log `options` as-is: `options.env` may carry a passphrase
    debugLog("execute_openssl", cmd, redactEnvForLog(options));
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
