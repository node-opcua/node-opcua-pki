import * as fs from "fs";
import * as path from "path";
import * as chalk from "chalk";
import { g_config } from "./config";
import assert = require("assert");
import { debugLog } from "./debug";

export function certificateFileExist(certificateFile: string): boolean {
    // istanbul ignore next
    if (fs.existsSync(certificateFile) && !g_config.force) {
        console.log(
            chalk.yellow("        certificate ") + chalk.cyan(certificateFile) + chalk.yellow(" already exists => do not overwrite")
        );
        return false;
    }
    return true;
}

export function mkdir(folder: string): void {
    if (!fs.existsSync(folder)) {
        // istanbul ignore next
        debugLog(chalk.white(" .. constructing "), folder);
        fs.mkdirSync(folder);
    }
}

export function make_path(folderName: string, filename?: string): string {
    let s;
    if (filename) {
        s = path.join(path.normalize(folderName), filename);
    } else {
        assert(folderName);
        s = folderName;
    }
    s = s.replace(/\\/g, "/");
    return s;
}
