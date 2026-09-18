import should from "should";
import { toFilenameLabel } from "../packages/node-opcua-pki/lib/pki/certificate_manager";
import { execute } from "../packages/node-opcua-pki/lib/toolbox/with_openssl/execute_openssl";

// Characters that must never appear in a stored filename label, because on a
// Windows ANSI code page a look-alike Unicode character can be "best-fit"
// mapped onto one of them and change how a later openssl command line is split.
const delimiters = /["\\/:]/;
const nonAscii = /[^\x20-\x7E]/;

// Fullwidth forms used by the classic argument-injection payload.
const FW_QUOTE = "\uFF02";
const FW_BACKSLASH = "\uFF3C";
const FW_COLON = "\uFF1A";
const FW_HYPHEN = "\uFF0D";

describe("stored certificate filename labels", () => {
    const bypassClasses: [string, string][] = [
        [
            "fullwidth quote/backslash/colon/hyphen",
            `a${FW_QUOTE} ${FW_HYPHEN}out ${FW_QUOTE}c${FW_BACKSLASH}x${FW_QUOTE} ${FW_HYPHEN}passin pass${FW_COLON}`
        ],
        ["fraction / division slash", "..\u2044..\u2215trusted\u2044evil"],
        ["set-minus", "a\u2216b"],
        ["curly double quotes", "a\u201C -out x\u201D"],
        ["primes / curly single quotes", "a\u2032\u2019\u2018"],
        ["unicode dashes", "a\u2010out\u2013x\u2014y\u2212z"],
        ["no-break / narrow spaces", "a\u00A0-out\u202Fx"],
        ["modifier letter colon", "c\uA789\\path"]
    ];

    for (const [name, commonName] of bypassClasses) {
        it(`neutralises ${name}`, () => {
            const label = toFilenameLabel(commonName);
            should(delimiters.test(label)).eql(false, `label must not contain " \\ / : -> ${JSON.stringify(label)}`);
            should(nonAscii.test(label)).eql(false, `label must be plain ASCII -> ${JSON.stringify(label)}`);
        });
    }

    it("keeps an ordinary ASCII common name readable", () => {
        should(toFilenameLabel("MyDevice-01")).eql("MyDevice-01");
    });

    it("folds decorative fullwidth letters to their ASCII base", () => {
        // ＭｙＤｅｖ
        should(toFilenameLabel("\uFF2D\uFF59\uFF24\uFF45\uFF56")).eql("MyDev");
    });

    it("falls back to a fixed label for an empty common name", () => {
        should(toFilenameLabel("")).eql("certificate");
    });

    it("caps the label length", () => {
        const label = toFilenameLabel("a".repeat(500));
        should(label.length).belowOrEqual(64);
    });
});

describe("openssl argument safety guard", () => {
    it("refuses an argument carrying fullwidth characters", async () => {
        let error: Error | undefined;
        try {
            await execute("openssl", ["x509", "-in", `x${FW_QUOTE} ${FW_HYPHEN}out y`, "-noout"], {});
        } catch (err) {
            error = err as Error;
        }
        should.exist(error);
        should((error as Error).message).match(/refusing argument/);
    });

    it("allows a non-ASCII letter in a path (accented user profile) — no false positive", async () => {
        // The guard must NOT trip on real letters; here the spawn fails for an
        // unrelated reason (no such binary), which proves the guard let it through.
        let error: Error | undefined;
        try {
            await execute("openssl-does-not-exist", ["x509", "-in", "C:\\Users\\Jos\u00E9\\pki\\cert.pem", "-noout"], {});
        } catch (err) {
            error = err as Error;
        }
        should.exist(error);
        should((error as Error).message).not.match(/refusing argument/);
    });
});
