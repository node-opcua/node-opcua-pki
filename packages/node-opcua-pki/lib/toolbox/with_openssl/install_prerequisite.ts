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

import child_process from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import byline from "byline";
import chalk from "chalk";
import yauzl from "yauzl";

import { warningLog } from "../debug";
import { buildChildEnv } from "./_env";

const doDebug = process.env.NODEOPCUAPKIDEBUG || false;

interface ExecuteResult {
    exitCode: number;
    output: string;
}

/**
 * Run `file` with `args` directly (no shell), same as execute_openssl's
 * `execute()`: the same curated environment (a binary discovered with the
 * full parent env but run with a reduced one could otherwise be found here
 * and then fail to load its libraries later), and /dev/null stdin.
 * Resolves with the exit code rather than rejecting on a non-zero exit;
 * rejects only when the process cannot be spawned at all.
 */
async function execute(file: string, args: string[], cwd?: string): Promise<ExecuteResult> {
    let output = "";

    return await new Promise<ExecuteResult>((resolve, reject) => {
        const child = child_process.spawn(file, args, {
            cwd,
            windowsHide: true,
            env: buildChildEnv(),
            stdio: ["ignore", "pipe", "pipe"]
        });
        child.on("error", (err: Error) => reject(err));
        child.on("close", (code: number | null) => resolve({ exitCode: code ?? 1, output }));

        const stream1 = byline(child.stdout as Readable);
        stream1.on("data", (line: string) => {
            output += `${line}\n`;
            // istanbul ignore next
            if (doDebug) {
                process.stdout.write(`        stdout ${chalk.yellow(line)}\n`);
            }
        });
    });
}

function is_expected_openssl_version(strVersion: string): boolean {
    return !!strVersion.match(/OpenSSL \d/);
}

async function getopensslExecPath(): Promise<string> {
    let result1: ExecuteResult | undefined;
    try {
        result1 = await execute("which", ["openssl"]);
    } catch (err) {
        warningLog("warning: ", (err as Error).message);
        throw new Error("Cannot find openssl");
    }

    const exitCode = result1?.exitCode;
    const output = result1?.output;

    if (exitCode !== 0) {
        warningLog(chalk.yellow(" it seems that ") + chalk.cyan("openssl") + chalk.yellow(" is not installed on your computer "));
        warningLog(chalk.yellow("Please install it before running this programs"));
        throw new Error("Cannot find openssl");
    }
    const opensslExecPath = output.replace(/\n\r/g, "").trim();
    return opensslExecPath;
}
export async function check_system_openssl_version(): Promise<string> {
    const opensslExecPath = await getopensslExecPath();

    // istanbul ignore next
    if (doDebug) {
        warningLog(`              OpenSSL found in : ${chalk.yellow(opensslExecPath)}`);
    }
    // ------------------------ now verify that openssl version is the correct one
    const result = await execute(opensslExecPath, ["version"]);

    const exitCode = result?.exitCode;
    const output = result?.output;

    const version = output.trim();

    const versionOK = exitCode === 0 && is_expected_openssl_version(version);
    if (!versionOK) {
        let message =
            chalk.whiteBright("Warning !!!!!!!!!!!! ") +
            "\nyour version of openssl is " +
            version +
            ". It doesn't match the expected version";

        if (process.platform === "darwin") {
            message +=
                chalk.cyan("\nplease refer to :") +
                chalk.yellow(" https://github.com/node-opcua/node-opcua/" + "wiki/installing-node-opcua-or-node-red-on-MacOS");
        }

        console.log(message);
    }
    return output;
}

async function install_and_check_win32_openssl_version(): Promise<string> {
    const downloadFolder = path.join(os.tmpdir(), ".");

    function get_openssl_folder_win32(): string {
        if (process.env.LOCALAPPDATA) {
            const userProgramFolder = path.join(process.env.LOCALAPPDATA, "Programs");
            if (fs.existsSync(userProgramFolder)) {
                return path.join(userProgramFolder, "openssl");
            }
        }
        return path.join(process.cwd(), "openssl");
    }

    function get_openssl_exec_path_win32(): string {
        const opensslFolder = get_openssl_folder_win32();
        return path.join(opensslFolder, "openssl.exe");
    }

    async function check_openssl_win32(): Promise<{ opensslOk?: boolean; version?: string }> {
        const opensslExecPath = get_openssl_exec_path_win32();

        const exists = fs.existsSync(opensslExecPath);
        if (!exists) {
            warningLog("checking presence of ", opensslExecPath);
            warningLog(chalk.red(" cannot find file ") + opensslExecPath);
            return {
                opensslOk: false,
                version: `cannot find file ${opensslExecPath}`
            };
        } else {
            const cwd = ".";

            const { exitCode, output } = await execute(opensslExecPath, ["version"], cwd);
            const version = output.trim();
            // istanbul ignore next

            if (doDebug) {
                warningLog(" Version = ", version);
            }
            return {
                opensslOk: exitCode === 0 && is_expected_openssl_version(version),
                version
            };
        }
    }

    /**
     * Try to find a system-installed openssl on Windows via `where`.
     * Returns the path if found and version is acceptable, otherwise undefined.
     */
    async function find_system_openssl_win32(): Promise<string | undefined> {
        try {
            const result = await execute("where", ["openssl"]);
            if (result.exitCode !== 0) {
                return undefined;
            }
            // `where` may return multiple lines; take the first one
            const opensslPath = result.output.split(/\r?\n/)[0].trim();
            if (!opensslPath || !fs.existsSync(opensslPath)) {
                return undefined;
            }
            // verify version
            const versionResult = await execute(opensslPath, ["version"]);
            const version = versionResult.output.trim();
            if (versionResult.exitCode === 0 && is_expected_openssl_version(version)) {
                warningLog(
                    chalk.green("Using system OpenSSL: ") + chalk.cyan(version) + chalk.green(" at ") + chalk.cyan(opensslPath)
                );
                return opensslPath;
            }
            warningLog(chalk.yellow("System OpenSSL found but version not accepted: ") + version);
            return undefined;
        } catch (_err) {
            return undefined;
        }
    }

    /**
     * detect whether windows OS is a 64 bits or 32 bits
     * http://ss64.com/nt/syntax-64bit.html
     * http://blogs.msdn.com/b/david.wang/archive/2006/03/26/howto-detect-process-bitness.aspx
     * @return {number}
     */
    function win32or64(): 32 | 64 {
        if (process.env.PROCESSOR_ARCHITECTURE === "x86" && process.env.PROCESSOR_ARCHITEW6432) {
            return 64;
        }

        if (process.env.PROCESSOR_ARCHITECTURE === "AMD64") {
            return 64;
        }

        // check if we are running node  x32 on a x64 arch
        if (process.env.CURRENT_CPU === "x64") {
            return 64;
        }
        return 32;
    }

    async function download_openssl(): Promise<{ downloadedFile: string }> {
        const url =
            win32or64() === 64
                ? "https://github.com/node-opcua/node-opcua-pki/releases/download/2.14.2/openssl-1.0.2u-x64_86-win64.zip"
                : "https://github.com/node-opcua/node-opcua-pki/releases/download/2.14.2/openssl-1.0.2u-i386-win32.zip";
        // the zip file
        const outputFilename = path.join(downloadFolder, path.basename(url));

        warningLog(`downloading ${chalk.yellow(url)} to ${outputFilename}`);

        if (fs.existsSync(outputFilename)) {
            return { downloadedFile: outputFilename };
        }

        const response = await fetch(url, { redirect: "follow" });
        if (!response.ok || !response.body) {
            throw new Error(`Failed to download OpenSSL from ${url}: ${response.status} ${response.statusText}`);
        }

        const contentLength = parseInt(response.headers.get("content-length") || "0", 10);
        let downloaded = 0;
        let lastPercent = -1;

        const fileStream = fs.createWriteStream(outputFilename);

        // Use pipeline for proper backpressure and cleanup
        const body = response.body as unknown as Readable;
        body.on("data", (chunk: Buffer) => {
            downloaded += chunk.length;
            if (contentLength > 0) {
                const percent = Math.floor((downloaded / contentLength) * 100);
                if (percent !== lastPercent && percent % 10 === 0) {
                    lastPercent = percent;
                    warningLog(`  download progress: ${percent}%`);
                }
            }
        });

        await pipeline(body, fileStream);

        // Verify the downloaded file exists and has content
        const stat = fs.statSync(outputFilename);
        if (stat.size === 0) {
            fs.unlinkSync(outputFilename);
            throw new Error(`Downloaded file is empty: ${outputFilename}`);
        }

        warningLog(chalk.green("Download complete: ") + `${stat.size} bytes`);
        return { downloadedFile: outputFilename };
    }

    async function unzip_openssl(zipFilename: string) {
        const opensslFolder = get_openssl_folder_win32();

        const zipFile = await new Promise<yauzl.ZipFile>((resolve, reject) => {
            yauzl.open(zipFilename, { lazyEntries: true }, (err?: Error | null, zipfile?: yauzl.ZipFile) => {
                if (err) {
                    reject(err);
                } else {
                    if (!zipfile) {
                        reject(new Error("zipfile is null"));
                    } else {
                        resolve(zipfile);
                    }
                }
            });
        });

        zipFile.readEntry();

        await new Promise<void>((resolve, reject) => {
            zipFile.on("end", (err?: Error) => {
                setImmediate(() => {
                    // istanbul ignore next
                    if (doDebug) {
                        warningLog("unzip done");
                    }
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });

            zipFile.on("entry", (entry: yauzl.Entry) => {
                zipFile.openReadStream(entry, (err?: Error | null, readStream?: Readable) => {
                    if (err) {
                        return reject(err);
                    }

                    const file = path.join(opensslFolder, entry.fileName);

                    // istanbul ignore next
                    if (doDebug) {
                        warningLog(" unzipping :", file);
                    }

                    const writeStream = fs.createWriteStream(file, "binary");
                    // ensure parent directory exists
                    readStream?.pipe(writeStream);

                    writeStream.on("close", () => {
                        zipFile.readEntry();
                    });
                });
            });
        });
    }

    // 1. Try system-installed OpenSSL first (e.g. on CI runners)
    const systemOpenssl = await find_system_openssl_win32();
    if (systemOpenssl) {
        return systemOpenssl;
    }

    // 2. Check bundled OpenSSL at the expected local path
    const opensslFolder = get_openssl_folder_win32();
    const opensslExecPath = get_openssl_exec_path_win32();

    if (!fs.existsSync(opensslFolder)) {
        // istanbul ignore next
        if (doDebug) {
            warningLog("creating openssl_folder", opensslFolder);
        }
        fs.mkdirSync(opensslFolder);
    }

    const { opensslOk, version: _version } = await check_openssl_win32();

    if (!opensslOk) {
        // 3. Download as last resort
        warningLog(chalk.yellow("openssl seems to be missing and need to be installed"));
        const { downloadedFile } = await download_openssl();

        // istanbul ignore next
        if (doDebug) {
            warningLog("deflating ", chalk.yellow(downloadedFile));
        }
        await unzip_openssl(downloadedFile);

        const opensslExists = !!fs.existsSync(opensslExecPath);

        // istanbul ignore next
        if (doDebug) {
            warningLog("verifying ", opensslExists, opensslExists ? chalk.green("OK ") : chalk.red(" Error"), opensslExecPath);
        }

        const _opensslExecPath2 = await check_openssl_win32();
        return opensslExecPath;
    } else {
        // istanbul ignore next
        if (doDebug) {
            warningLog(chalk.green("openssl is already installed and have the expected version."));
        }
        return opensslExecPath;
    }
}

/**
 *
 * return path to the openssl executable
 */
export async function install_prerequisite(): Promise<string> {
    // istanbul ignore else
    if (process.platform !== "win32") {
        return await check_system_openssl_version();
    } else {
        return await install_and_check_win32_openssl_version();
    }
}

export async function get_openssl_exec_path(): Promise<string> {
    if (process.platform === "win32") {
        const opensslExecPath = await install_prerequisite();
        if (!fs.existsSync(opensslExecPath)) {
            throw new Error(`internal error cannot find ${opensslExecPath}`);
        }
        return opensslExecPath;
    } else {
        return "openssl";
    }
}
