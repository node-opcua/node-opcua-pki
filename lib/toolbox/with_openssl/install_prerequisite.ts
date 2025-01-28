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

import fs from "fs";
import os from "os";
import path from "path";
import url from "url";
import byline from "byline";
import chalk from "chalk";
import child_process from "child_process";
import ProgressBar from "progress";
import yauzl from "yauzl";
import { Readable } from "stream";

import Table = require("cli-table");
import { warningLog } from "../debug";

const doDebug = process.env.NODEOPCUAPKIDEBUG || false;

declare interface ProxyOptions {
    host: string;
    port: number;
    localAddress?: string;
    proxyAuth?: string;
    headers?: { [key: string]: any };
    protocol: string; // "https" | "http"
}
declare interface WgetOptions {
    gunzip?: boolean;
    proxy?: ProxyOptions;
}

declare interface WgetInterface {
    download(url: string, outputFilename: string, options: WgetOptions): any;
}

// tslint:disable-next-line:no-var-requires
// eslint-disable-next-line @typescript-eslint/no-var-requires
const wget = require("wget-improved-2") as WgetInterface;

interface ExecuteResult {
    exitCode: number;
    output: string;
}

function makeOptions(): WgetOptions {
    const proxy =
        process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy || undefined;
    if (proxy) {
        const a = new url.URL(proxy);
        const auth = a.username ? a.username + ":" + a.password : undefined;

        const options: WgetOptions = {
            proxy: {
                port: a.port ? parseInt(a.port, 10) : 80,
                protocol: a.protocol.replace(":", ""),
                host: a.hostname ?? "",
                proxyAuth: auth,
            },
        };
        warningLog(chalk.green("- using proxy "), proxy);
        warningLog(options);
        return options;
    }
    return {};
}

async function execute(cmd: string, cwd?: string): Promise<ExecuteResult> {
    let output = "";

    // xx cwd = cwd ? {cwd: cwd} : {};
    const options = {
        cwd,
        windowsHide: true,
    };

    return await new Promise<ExecuteResult>((resolve, reject) => {
        const child = child_process.exec(
            cmd,
            options,
            (err: child_process.ExecException | null /*, stdout: string, stderr: string*/) => {
                const exitCode = err === null ? 0 : err!.code!;
                if (err) reject(err);
                else {
                    resolve({ exitCode, output });
                }
            },
        );

        const stream1 = byline(child.stdout!);
        stream1.on("data", (line: string) => {
            output += line + "\n";
            // istanbul ignore next
            if (doDebug) {
                process.stdout.write("        stdout " + chalk.yellow(line) + "\n");
            }
        });
    });
}

function quote(str: string): string {
    return '"' + str.replace(/\\/g, "/") + '"';
}

function is_expected_openssl_version(strVersion: string): boolean {
    return !!strVersion.match(/OpenSSL 1|3/);
}

async function getopensslExecPath(): Promise<string> {
    let result1: ExecuteResult | undefined;
    try {
        result1 = await execute("which openssl");
    } catch (err) {
        warningLog("warning: ", (err as Error).message);
        throw new Error("Cannot find openssl");
    }

    const exitCode = result1!.exitCode;
    const output = result1!.output;

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

    // tslint:disable-next-line:variable-name
    const q_opensslExecPath = quote(opensslExecPath);

    // istanbul ignore next
    if (doDebug) {
        warningLog("              OpenSSL found in : " + chalk.yellow(opensslExecPath));
    }
    // ------------------------ now verify that openssl version is the correct one
    const result = await execute(q_opensslExecPath + " version");

    const exitCode = result!.exitCode;
    const output = result!.output;

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

        const table = new Table();
        table.push([message]);
        console.error(table.toString());
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
                version: "cannot find file " + opensslExecPath,
            };
        } else {
            // tslint:disable-next-line:variable-name
            const q_openssl_exe_path = quote(opensslExecPath);
            const cwd = ".";

            const { exitCode, output } = await execute(q_openssl_exe_path + " version", cwd);
            const version = output.trim();
            // istanbul ignore next

            if (doDebug) {
                warningLog(" Version = ", version);
            }
            return {
                opensslOk: exitCode === 0 && is_expected_openssl_version(version),
                version,
            };
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
        // const url = (win32or64() === 64 )
        //         ? "http://indy.fulgan.com/SSL/openssl-1.0.2o-x64_86-win64.zip"
        //         : "http://indy.fulgan.com/SSL/openssl-1.0.2o-i386-win32.zip"
        //     ;
        const url =
            win32or64() === 64
                ? "https://github.com/node-opcua/node-opcua-pki/releases/download/2.14.2/openssl-1.0.2u-x64_86-win64.zip"
                : "https://github.com/node-opcua/node-opcua-pki/releases/download/2.14.2/openssl-1.0.2u-i386-win32.zip";
        // the zip file
        const outputFilename = path.join(downloadFolder, path.basename(url));

        warningLog("downloading " + chalk.yellow(url) + " to " + outputFilename);

        if (fs.existsSync(outputFilename)) {
            return { downloadedFile: outputFilename };
        }
        const options = makeOptions();
        const bar = new ProgressBar(chalk.cyan("[:bar]") + chalk.cyan(" :percent ") + chalk.white(":etas"), {
            complete: "=",
            incomplete: " ",
            total: 100,
            width: 100,
        });

        return await new Promise((resolve, reject) => {
            const download = wget.download(url, outputFilename, options);
            download.on("error", (err: Error) => {
                warningLog(err);
                setImmediate(() => {
                    reject(err);
                });
            });
            download.on("end", (output: string) => {
                // istanbul ignore next
                if (doDebug) {
                    warningLog(output);
                }
                // warningLog("done ...");
                resolve({ downloadedFile: outputFilename });
            });
            download.on("progress", (progress: any) => {
                bar.update(progress);
            });
        });
    }

    async function unzip_openssl(zipFilename: string) {
        const opensslFolder = get_openssl_folder_win32();

        const zipFile = await new Promise<yauzl.ZipFile>((resolve, reject) => {
            yauzl.open(zipFilename, { lazyEntries: true }, (err?: Error | null, zipfile?: yauzl.ZipFile) => {
                if (err) {
                    reject(err);
                }
                resolve(zipfile!);
            });
        });

        zipFile.readEntry();

        await new Promise((resolve, reject) => {
            zipFile.on("end", (err?: Error) => {
                setImmediate(() => {
                    // istanbul ignore next
                    if (doDebug) {
                        warningLog("unzip done");
                    }
                    reject(err);
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
                    readStream!.pipe(writeStream);

                    writeStream.on("close", () => {
                        zipFile.readEntry();
                    });
                });
            });
        });
    }

    const opensslFolder = get_openssl_folder_win32();
    const opensslExecPath = get_openssl_exec_path_win32();

    if (!fs.existsSync(opensslFolder)) {
        // istanbul ignore next
        if (doDebug) {
            warningLog("creating openssl_folder", opensslFolder);
        }
        fs.mkdirSync(opensslFolder);
    }

    const { opensslOk, version } = await check_openssl_win32();

    if (!opensslOk) {
        warningLog(chalk.yellow("openssl seems to be missing and need to be installed"));
        const { downloadedFile } = await download_openssl();

        // istanbul ignore next
        if (doDebug) {
            warningLog("deflating ", chalk.yellow(downloadedFile!));
        }
        await unzip_openssl(downloadedFile);

        const opensslExists = !!fs.existsSync(opensslExecPath);

        // istanbul ignore next
        if (doDebug) {
            warningLog("verifying ", opensslExists, opensslExists ? chalk.green("OK ") : chalk.red(" Error"), opensslExecPath);
        }

        const opensslExecPath2 = await check_openssl_win32();
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
        if (!fs.existsSync(opensslExecPath!)) {
            throw new Error("internal error cannot find " + opensslExecPath);
        }
        return opensslExecPath;
    } else {
        return "openssl";
    }
}
