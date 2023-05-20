
import * as chalk from "chalk";
import { g_config } from "./config";

// istanbul ignore next
export function displayChapter(str: string, callback?: (err?: Error) => void) {
    const l = "                                                                                               ";
    console.log(chalk.bgWhite(l) + " ");
    str = ("        " + str + l).substring(0, l.length);
    console.log(chalk.bgWhite.cyan(str));
    console.log(chalk.bgWhite(l) + " ");
    if (callback) {
        callback();
    }
}

export function displayTitle(str: string, callback?: (err?: Error) => void) {
    // istanbul ignore next
    if (!g_config.silent) {
        console.log("");
        console.log(chalk.yellowBright(str));
        console.log(chalk.yellow(new Array(str.length + 1).join("=")), "\n");
    }
    if (callback) {
        callback();
    }
}

export function displaySubtitle(str: string, callback?: (err?: Error) => void) {
    // istanbul ignore next
    if (!g_config.silent) {
        console.log("");
        console.log("    " + chalk.yellowBright(str));
        console.log("    " + chalk.white(new Array(str.length + 1).join("-")), "\n");
    }
    if (callback) {
        callback();
    }
}
export function display(str: string, callback?: (err?: Error) => void) {
    // istanbul ignore next
    if (!g_config.silent) {
        console.log("       " + str);
    }
    if (callback) {
        callback();
    }
}