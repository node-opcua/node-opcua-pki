import * as assert from "assert";
import * as crypto from "crypto";

export function makeApplicationUrn(hostname: string, suffix: string): string {

    // beware : Openssl doesn't support urn with length greater than 64 !!
    //          sometimes hostname length could be too long ...
    // application urn length must not exceed 64 car. to comply with openssl
    // see cryptoCA
    let hostnameHash = hostname;
    if (hostnameHash.length + 7 + suffix.length >= 64) {
        // we need to reduce the applicationUrn side => let's take
        // a portion of the hostname hash.
        hostnameHash = crypto.createHash("md5")
            .update(hostname)
            .digest("hex")
            .substr(0, 16);
    }

    const applicationUrn = "urn:" + hostnameHash + ":" + suffix;
    assert(applicationUrn.length <= 64);
    return applicationUrn;
}
