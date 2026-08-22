// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-pki
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2026 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
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

import { type OpensslPassArg, passinArg, setEnv, unsetEnv } from "../toolbox/with_openssl";
import { NativeCaBackend } from "./backends/native_ca_backend";
import { caConfigEnvOverrides, OpenSslCaBackend } from "./backends/openssl_ca_backend";
import { CertificateAuthorityCore, type CertificateAuthorityCoreOptions } from "./core/certificate_authority_core";

// Everything the CA exposes lives in the core module; re-exported here so
// that `import { ... } from "./ca/certificate_authority"` keeps resolving
// exactly as it did before the split.
export * from "./core/certificate_authority_core";

/**
 * Options for {@link CertificateAuthority}: the core's, except that the
 * backend is named rather than supplied.
 */
export interface CertificateAuthorityOptions extends Omit<CertificateAuthorityCoreOptions, "backend"> {
    /**
     * Signing backend to use.
     *
     * - `"openssl"` (default): shells out to the `openssl` CLI, as this
     *   class always has.
     * - `"native"`: signs in pure JS via `node-opcua-crypto`, writing the
     *   same on-disk database format, and needs no `openssl` executable.
     *
     * Setting `signer` implies `"native"`, since the openssl CLI can only
     * load a key from a file.
     *
     * To supply a backend instance directly - including one of your own -
     * use {@link CertificateAuthorityCore}, which is also the class to
     * build against when you do not want the openssl backend in your
     * bundle at all.
     */
    backend?: "openssl" | "native";
}

/**
 * A Certificate Authority with a backend chosen for you.
 *
 * This is {@link CertificateAuthorityCore} plus the convenience that made
 * it the historical API: name a backend, or name nothing and get openssl.
 * Because it resolves the name, it necessarily references both backends,
 * which is why the core exists separately - a program that never imports
 * this class never pulls the openssl backend into its bundle.
 */
export class CertificateAuthority extends CertificateAuthorityCore {
    constructor(options: CertificateAuthorityOptions) {
        if (options.signer && options.backend === "openssl") {
            throw new Error(
                "CertificateAuthority: backend 'openssl' cannot be combined with 'signer' - " +
                    "the openssl CLI loads its key from a file and cannot call an external signer. " +
                    "Drop the backend option (a signer implies 'native') or drop the signer."
            );
        }
        const backend = options.signer || options.backend === "native" ? new NativeCaBackend() : new OpenSslCaBackend();
        super({ ...options, backend });
    }

    /**
     * @internal `-passin env:` argv + env for an openssl call that loads
     * this CA's key (always emitted, empty when none).
     *
     * The openssl backend builds its own now; this remains so that external
     * code calling it keeps working, and lives here rather than on the core
     * because the flag means nothing to a backend that spawns nothing.
     */
    public async _opensslPassin(): Promise<OpensslPassArg> {
        return passinArg(await this._privateKeyPassphrase());
    }

    /**
     * @internal
     * Legacy shim: publish the `CDP_URL` / `AIA_VALUE` config substitution
     * values to the shared env registry, or unset them so the matching
     * `{{#KEY}}...{{/KEY}}` blocks are stripped. Nothing in this package
     * reads the registry any more - every openssl config render receives
     * these values explicitly, from the same {@link caConfigEnvOverrides}
     * builder this delegates to, so the two cannot drift - kept only for
     * external code that renders openssl config templates against the
     * registry directly.
     *
     * It lives on this class rather than the core because it is meaningful
     * only to the openssl backend.
     */
    public _wireRevocationEnvVars(): void {
        const overrides = caConfigEnvOverrides(this);
        if (overrides.CDP_URL) {
            setEnv("CDP_URL", overrides.CDP_URL);
        } else {
            unsetEnv("CDP_URL");
        }
        if (overrides.AIA_VALUE) {
            setEnv("AIA_VALUE", overrides.AIA_VALUE);
        } else {
            unsetEnv("AIA_VALUE");
        }
    }
}
