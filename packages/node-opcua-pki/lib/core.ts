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

/**
 * `node-opcua-pki/core` - a Certificate Authority with no `openssl` in it.
 *
 * The package entry point gives you {@link CertificateAuthority}, which
 * chooses a backend for you and therefore references the openssl one
 * whether or not you use it. This entry point does not: it ships
 * {@link CertificateAuthorityCore}, which takes a backend, and the native
 * backend to give it, and nothing that reaches the `openssl` executable.
 *
 * Use it when bundle size matters, or when the `openssl` binary will not be
 * present at runtime.
 *
 * ```ts
 * import { CertificateAuthorityCore, NativeCaBackend } from "node-opcua-pki/core";
 *
 * const ca = new CertificateAuthorityCore({
 *     keySize: 2048,
 *     location: "/var/pki/CA",
 *     backend: new NativeCaBackend()
 * });
 * await ca.initialize();
 * ```
 *
 * Pass a `signer` as well to keep the CA key in an HSM or KMS - see
 * `hsm-kms-signing.md`.
 *
 * The one behavioural difference from the default entry point is the CA
 * certificate: a directory created here is still a valid `openssl ca`
 * directory, so external openssl tooling can take it over later.
 */
export { NativeCaBackend } from "./ca/backends/native_ca_backend";
export * from "./ca/core";
export * from "./misc/subject";
