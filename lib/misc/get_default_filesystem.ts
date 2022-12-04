import * as fs from "./fs";


export function getDefaultFileSystem(): fs.FileSystem {
    return fs as fs.FileSystem;
}
