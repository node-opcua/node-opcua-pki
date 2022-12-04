// import * as _fs from "memfs";

import { vol, fs, IFs} from "memfs";
import { EventEmitter } from "node:events";
// export const fs = _fs;

const json = {
    "/sterfive/NodeOPCUA/node-opcua-pki/tmp": null,
    "/Users/etien/AppData/Local/Temp/": null
};
vol.fromJSON(json,"/");

export const writeFileSync = fs.writeFileSync;
export const writeFile = fs.writeFile;
export const existsSync = fs.existsSync;
export const readFileSync = fs.readFileSync;
export const unlink =fs.unlink;
export const mkdirSync = fs.mkdirSync;
export const rename = fs.rename;
export const createWriteStream = fs.createWriteStream;

export type FileSystem = IFs;
export interface FSWatcher extends EventEmitter {
    /** */
    close(): void;
}
export interface Stats {
    /** */
    a: number;
}
export const promises = fs.promises;

