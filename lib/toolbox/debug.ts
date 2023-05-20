


export const doDebug = process.env.NODEOPCUAPKIDEBUG || false;
export const displayError = true;
export const displayDebug = !!process.env.NODEOPCUAPKIDEBUG || false;
// tslint:disable-next-line:no-empty
export function debugLog(...args: [any?, ...any[]]) {
    // istanbul ignore next
    if (displayDebug) {
        console.log.apply(null, args);
    }
}

