// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022 - Sterfive.com
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

export interface SubjectOptions {
    commonName?: string;
    organization?: string;
    organizationalUnit?: string;
    locality?: string;
    state?: string;
    country?: string;
    domainComponent?: string;
}

const _keys = {
    C: "country",
    CN: "commonName",
    DC: "domainComponent",
    L: "locality",
    O: "organization",
    OU: "organizationalUnit",
    ST: "state",
};

const enquoteIfNecessary = (str: string) => {
    str = str.replace(/"/g, "”");
    return str.match(/\/|=/) ? `"${str}"` : str;
};
const unquote = (str: string) => str.replace(/"/gm, "");
const unquote2 = (str?: string | undefined) => {
    if (!str) return str;
    const m = str.match(/^"(.*)"$/);
    return m ? m[1] : str;
};
/**
 * subjectName	The subject name to use for the Certificate.
 * If not specified the ApplicationName and/or domainNames are used to create a suitable default value.
 */
export class Subject implements SubjectOptions {
    public readonly commonName?: string;
    public readonly organization?: string;
    public readonly organizationalUnit?: string;
    public readonly locality?: string;
    public readonly state?: string;
    public readonly country?: string;
    public readonly domainComponent?: string;

    constructor(options: SubjectOptions | string) {
        if (typeof options === "string") {
            options = Subject.parse(options);
        }
        this.commonName = unquote2(options.commonName);
        this.organization = unquote2(options.organization);
        this.organizationalUnit = unquote2(options.organizationalUnit);
        this.locality = unquote2(options.locality);
        this.state = unquote2(options.state);
        this.country = unquote2(options.country);
        this.domainComponent = unquote2(options.domainComponent);
    }

    public static parse(str: string): SubjectOptions {
        const elements = str.split(/\/(?=[^/]*?=)/);
        const options: Record<string, unknown> = {};

        elements.forEach((element: string) => {
            if (element.length === 0) {
                return;
            }
            const s: string[] = element.split("=");

            if (s.length !== 2) {
                throw new Error("invalid format for " + element);
            }
            const longName = (_keys as Record<string, string>)[s[0]];
            if (!longName) {
                throw new Error("Invalid field found in subject name " + s[0]);
            }
            const value = s[1];
            options[longName] = unquote(Buffer.from(value, "ascii").toString("utf8"));
        });
        return options as SubjectOptions;
    }

    public toStringForOPCUA(): string {
        // https://reference.opcfoundation.org/v104/GDS/docs/7.6.4/
        // The format of the subject name is a sequence of name value pairs separated by a ‘/’.
        // The name shall be one of ‘CN’, ‘O’, ‘OU’, ‘DC’, ‘L’, ‘S’ or ‘C’ and
        // shall be followed by a ‘=’ and then followed by the value.
        // The value may be any printable character except for ‘”’.
        // If the value contains a ‘/’ or a ‘=’ then it shall be enclosed in double quotes (‘”’).

        const tmp: string[] = [];
        if (this.country) {
            tmp.push("C=" + enquoteIfNecessary(this.country));
        }
        if (this.state) {
            tmp.push("ST=" + enquoteIfNecessary(this.state));
        }
        if (this.locality) {
            tmp.push("L=" + enquoteIfNecessary(this.locality));
        }
        if (this.organization) {
            tmp.push("O=" + enquoteIfNecessary(this.organization));
        }
        if (this.organizationalUnit) {
            tmp.push("OU=" + enquoteIfNecessary(this.organizationalUnit));
        }
        if (this.commonName) {
            tmp.push("CN=" + enquoteIfNecessary(this.commonName));
        }
        if (this.domainComponent) {
            tmp.push("DC=" + enquoteIfNecessary(this.domainComponent));
        }
        return tmp.join("/");
    }
    public toString(): string {
        // standard for SSL is to have a / in front of each Field
        // see https://www.digicert.com/kb/ssl-support/openssl-quick-reference-guide.htm
        const t = this.toStringForOPCUA();
        return t ? "/" + t : t;
    }
}
