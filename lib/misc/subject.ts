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

export class Subject implements SubjectOptions {

    public readonly commonName?: string;
    public readonly organization?: string;
    public readonly organizationalUnit?: string;
    public readonly locality?: string;
    public readonly state?: string;
    public readonly country?: string;
    public readonly domainComponent?: string;

    constructor(options: SubjectOptions | string) {

        if (typeof(options) === "string") {
            options = Subject.parse(options);
        }
        this.commonName = options.commonName;
        this.organization = options.organization;
        this.organizationalUnit = options.organizationalUnit;
        this.locality = options.locality;
        this.state = options.state;
        this.country = options.country;
        this.domainComponent = options.domainComponent;
    }

    public static parse(str: string): SubjectOptions {

        const elements = str.split("/");
        const options: any = {};

        elements.forEach((element: string) => {
            if (element.length === 0) {
                return;
            }
            const s: string[] = element.split("=");

            if (s.length !== 2) {
                    throw new Error("invalid format for " + element);
            }
            const longName = (_keys as any)[s[0]];
            const value = s[1];
            options[longName] = Buffer.from(value,"ascii").toString("utf8");
        });
        return options as SubjectOptions;
    }

    public toString() {

        let tmp = "";
        if (this.country) {
            tmp += "/C=" + this.country;
        }
        if (this.state) {
            tmp += "/ST=" + this.state;
        }
        if (this.locality) {
            tmp += "/L=" + this.locality;
        }
        if (this.organization) {
            tmp += "/O=" + this.organization;
        }
        if (this.organizationalUnit) {
            tmp += "/OU=" + this.organization;
        }
        if (this.commonName) {
            tmp += "/CN=" + this.commonName;
        }
        if (this.domainComponent) {
            tmp += "/DC=" + this.domainComponent;
        }
        return tmp;
    }

}
