// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
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
import * as chalk from "chalk";
import { g_config } from "./config";
import { warningLog } from "./debug";

// istanbul ignore next
export function displayChapter(str: string, callback?: (err?: Error) => void) {
    const l = "                                                                                               ";
    warningLog(chalk.bgWhite(l) + " ");
    str = ("        " + str + l).substring(0, l.length);
    warningLog(chalk.bgWhite.cyan(str));
    warningLog(chalk.bgWhite(l) + " ");
    if (callback) {
        callback();
    }
}

export function displayTitle(str: string, callback?: (err?: Error) => void) {
    // istanbul ignore next
    if (!g_config.silent) {
        warningLog("");
        warningLog(chalk.yellowBright(str));
        warningLog(chalk.yellow(new Array(str.length + 1).join("=")), "\n");
    }
    if (callback) {
        callback();
    }
}

export function displaySubtitle(str: string, callback?: (err?: Error) => void) {
    // istanbul ignore next
    if (!g_config.silent) {
        warningLog("");
        warningLog("    " + chalk.yellowBright(str));
        warningLog("    " + chalk.white(new Array(str.length + 1).join("-")), "\n");
    }
    if (callback) {
        callback();
    }
}
export function display(str: string, callback?: (err?: Error) => void) {
    // istanbul ignore next
    if (!g_config.silent) {
        warningLog("       " + str);
    }
    if (callback) {
        callback();
    }
}
