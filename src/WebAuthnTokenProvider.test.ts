// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Samu Lang
// Copyright (c) 2026 Jesse Wright

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import {
    TOKEN_EXCHANGE_GRANT_TYPE,
    WEBAUTHN_ASSERTION_TOKEN_TYPE,
    BUNDLE_VERSION,
    decodeAssertionBundle,
} from "@jeswr/solid-webauthn-protocol"
import { WebAuthnTokenProvider } from "./WebAuthnTokenProvider.js"

const OP = "https://op.example"
const POD = "https://pod.example"
const POD_HOST = "pod.example"

const ASSERTION_OPTIONS = {
    challenge: "Y2hhbGxlbmdl", // base64url "challenge"
    rpId: "app.example",
    allowCredentials: [{ id: "Y3JlZC1pZA", type: "public-key" }],
    userVerification: "required" as const,
    timeout: 60000,
}

const ACCESS_TOKEN = "the.access.token"

/** A `navigator.credentials.get` result, with ArrayBuffer fields as required. */
function fakeCredential() {
    const buf = (s: string) => new TextEncoder().encode(s).buffer
    return {
        id: "Y3JlZC1pZA",
        rawId: buf("cred-id"),
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
            authenticatorData: buf("authData"),
            clientDataJSON: buf('{"type":"webauthn.get"}'),
            signature: buf("sig"),
            userHandle: buf("user"),
        },
        getClientExtensionResults: () => ({}),
    }
}

let credentialsGet: ReturnType<typeof vi.fn>

beforeEach(() => {
    // Make `browserSupportsWebAuthn()` pass.
    vi.stubGlobal("PublicKeyCredential", function () {})

    credentialsGet = vi.fn(async () => fakeCredential())
    vi.stubGlobal("navigator", { credentials: { get: credentialsGet } })
})

afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
})

/**
 * Install a `fetch` mock that answers the assertion-options `GET`, then the
 * token-exchange `POST`. Records every call for assertions.
 */
function mockFetch() {
    const calls: { url: string; init?: RequestInit }[] = []
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
        calls.push({ url, init })

        if (url.includes("assertion-options")) {
            return new Response(JSON.stringify(ASSERTION_OPTIONS), {
                status: 200,
                headers: { "content-type": "application/json" },
            })
        }
        if (url.includes("/token")) {
            return new Response(
                JSON.stringify({ access_token: ACCESS_TOKEN, token_type: "DPoP" }),
                { status: 200, headers: { "content-type": "application/json" } },
            )
        }
        throw new Error(`unexpected fetch: ${url}`)
    })
    vi.stubGlobal("fetch", fetchMock)
    return { calls, fetchMock }
}

describe("WebAuthnTokenProvider", () => {
    const config = {
        [POD_HOST]: {
            issuer: OP,
            assertionOptionsEndpoint: `${OP}/.oidc/webauthn/assertion-options`,
            tokenEndpoint: `${OP}/.oidc/token`,
        },
    }

    describe("matches", () => {
        it("matches a configured host", async () => {
            const provider = new WebAuthnTokenProvider(config)
            expect(await provider.matches(new Request(`${POD}/resource`))).toBe(true)
        })

        it("does not match an unconfigured host", async () => {
            const provider = new WebAuthnTokenProvider(config)
            expect(await provider.matches(new Request("https://other.example/x"))).toBe(false)
        })
    })

    describe("upgrade", () => {
        it("runs options -> get -> token-exchange and sets the DPoP Authorization", async () => {
            const { calls } = mockFetch()
            const provider = new WebAuthnTokenProvider(config)

            const upgraded = await provider.upgrade(new Request(`${POD}/resource`))

            // (b) options fetched first, by GET.
            expect(calls[0]!.url).toContain("assertion-options")
            expect((calls[0]!.init?.method ?? "GET")).toBe("GET")

            // (c) the WebAuthn ceremony ran with the challenge from options.
            expect(credentialsGet).toHaveBeenCalledOnce()
            const getArg = credentialsGet.mock.calls[0]![0] as { publicKey: PublicKeyCredentialRequestOptions }
            expect(getArg.publicKey.challenge).toBeInstanceOf(ArrayBuffer)

            // (e) token exchange POSTed second with the RFC 8693 params + a DPoP proof.
            const tokenCall = calls[1]!
            expect(tokenCall.url).toContain("/token")
            expect(tokenCall.init?.method).toBe("POST")
            const body = tokenCall.init?.body as URLSearchParams
            expect(body.get("grant_type")).toBe(TOKEN_EXCHANGE_GRANT_TYPE)
            expect(body.get("subject_token_type")).toBe(WEBAUTHN_ASSERTION_TOKEN_TYPE)
            const tokenHeaders = new Headers(tokenCall.init?.headers)
            expect(tokenHeaders.get("DPoP")).toBeTruthy()

            // (d) the subject_token is a well-formed, versioned assertion bundle.
            const subjectToken = body.get("subject_token")!
            const bundle = decodeAssertionBundle(subjectToken)
            expect(bundle.version).toBe(BUNDLE_VERSION)
            expect(bundle.credential.id).toBe("Y3JlZC1pZA")

            // (f) upgraded request carries DPoP Authorization + a resource-bound proof.
            expect(upgraded.headers.get("Authorization")).toBe(`DPoP ${ACCESS_TOKEN}`)
            expect(upgraded.headers.get("DPoP")).toBeTruthy()
            expect(upgraded.headers.get("DPoP")).not.toBe(tokenHeaders.get("DPoP"))
            expect(upgraded.url).toBe(`${POD}/resource`)
        })

        it("defaults the options endpoint and discovers the token endpoint", async () => {
            const calls: string[] = []
            vi.stubGlobal(
                "fetch",
                vi.fn(async (input: string | URL | Request) => {
                    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
                    calls.push(url)
                    if (url.includes(".well-known/openid-configuration")) {
                        return new Response(
                            JSON.stringify({
                                issuer: OP,
                                token_endpoint: `${OP}/discovered-token`,
                            }),
                            { status: 200, headers: { "content-type": "application/json" } },
                        )
                    }
                    if (url.includes("assertion-options")) {
                        return new Response(JSON.stringify(ASSERTION_OPTIONS), { status: 200 })
                    }
                    return new Response(JSON.stringify({ access_token: ACCESS_TOKEN, token_type: "DPoP" }), {
                        status: 200,
                    })
                }),
            )
            const provider = new WebAuthnTokenProvider({ [POD_HOST]: { issuer: OP } })

            await provider.upgrade(new Request(`${POD}/resource`))

            // assertion-options defaults to the conventional path under the issuer.
            expect(calls.some((u) => u === `${OP}/.oidc/webauthn/assertion-options`)).toBe(true)
            // token endpoint comes from OIDC discovery.
            expect(calls.some((u) => u === `${OP}/discovered-token`)).toBe(true)
        })

        it("falls back to the conventional token path when discovery fails", async () => {
            const calls: string[] = []
            vi.stubGlobal(
                "fetch",
                vi.fn(async (input: string | URL | Request) => {
                    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
                    calls.push(url)
                    if (url.includes(".well-known/openid-configuration")) {
                        return new Response("nope", { status: 404 })
                    }
                    if (url.includes("assertion-options")) {
                        return new Response(JSON.stringify(ASSERTION_OPTIONS), { status: 200 })
                    }
                    return new Response(JSON.stringify({ access_token: ACCESS_TOKEN, token_type: "DPoP" }), {
                        status: 200,
                    })
                }),
            )
            const provider = new WebAuthnTokenProvider({ [POD_HOST]: { issuer: OP } })

            await provider.upgrade(new Request(`${POD}/resource`))

            expect(calls.some((u) => u === `${OP}/.oidc/token`)).toBe(true)
        })

        it("throws when no configuration matches", async () => {
            mockFetch()
            const provider = new WebAuthnTokenProvider(config)
            await expect(
                provider.upgrade(new Request("https://other.example/x")),
            ).rejects.toThrow(/No WebAuthn configuration/)
        })

        it("throws when the assertion-options request fails", async () => {
            vi.stubGlobal(
                "fetch",
                vi.fn(async () => new Response("nope", { status: 500 })),
            )
            const provider = new WebAuthnTokenProvider(config)
            await expect(provider.upgrade(new Request(`${POD}/resource`))).rejects.toThrow(
                /Assertion-options request failed/,
            )
            expect(credentialsGet).not.toHaveBeenCalled()
        })

        it("retries the token exchange once on a use_dpop_nonce challenge", async () => {
            let tokenCalls = 0
            const nonces: (string | null)[] = []
            vi.stubGlobal(
                "fetch",
                vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
                    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
                    if (url.includes("assertion-options")) {
                        return new Response(JSON.stringify(ASSERTION_OPTIONS), { status: 200 })
                    }
                    // token endpoint
                    nonces.push(new Headers(init?.headers).get("DPoP"))
                    tokenCalls += 1
                    if (tokenCalls === 1) {
                        return new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
                            status: 400,
                            headers: { "DPoP-Nonce": "server-nonce" },
                        })
                    }
                    return new Response(JSON.stringify({ access_token: ACCESS_TOKEN, token_type: "DPoP" }), {
                        status: 200,
                    })
                }),
            )

            const provider = new WebAuthnTokenProvider(config)
            const upgraded = await provider.upgrade(new Request(`${POD}/resource`))

            expect(tokenCalls).toBe(2)
            expect(upgraded.headers.get("Authorization")).toBe(`DPoP ${ACCESS_TOKEN}`)
            // The retry used a fresh proof (different from the first).
            expect(nonces[0]).not.toBe(nonces[1])
        })
    })
})
