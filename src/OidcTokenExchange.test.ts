// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Samu Lang
// Copyright (c) 2026 Jesse Wright

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import * as oauth from "oauth4webapi"
import { OidcTokenExchange } from "./OidcTokenExchange.js"

// oauth4webapi rejects non-HTTPS discovery, so use an https issuer that maps via
// the .solidcommunity.net branch in #getIssuer.
const ISSUER = "https://solidcommunity.net"
const RESOURCE = "https://alice.solidcommunity.net/profile/"
const ACCESS_TOKEN = "oidc.access.token"

const CLIENT_ID = "client-abc"

const AS_METADATA = {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    registration_endpoint: `${ISSUER}/register`,
    jwks_uri: `${ISSUER}/jwks`,
    code_challenge_methods_supported: ["S256"],
}

let codeCalls: { uri: URL }[]

const b64url = (bytes: Uint8Array) =>
    Buffer.from(bytes).toString("base64url")

/**
 * Mint an ES256-signed OIDC id_token (with the given `nonce`) and expose the
 * matching JWKS so oauth4webapi can validate the authorization-code response
 * (`scope=openid` requires an id_token whose nonce echoes the auth request).
 */
async function makeIdTokenSigner(): Promise<{
    sign: (nonce: string) => Promise<string>
    jwk: JsonWebKey
}> {
    const { privateKey, publicKey } = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
    )
    const jwk = await crypto.subtle.exportKey("jwk", publicKey)
    jwk.alg = "ES256"
    jwk.use = "sig"

    const sign = async (nonce: string): Promise<string> => {
        const now = Math.floor(Date.now() / 1000)
        const header = { alg: "ES256", typ: "JWT" }
        const payload = { iss: ISSUER, sub: "alice", aud: CLIENT_ID, iat: now, exp: now + 3600, nonce }
        const signingInput = `${b64url(new TextEncoder().encode(JSON.stringify(header)))}.${b64url(
            new TextEncoder().encode(JSON.stringify(payload)),
        )}`
        const sig = new Uint8Array(
            await crypto.subtle.sign(
                { name: "ECDSA", hash: "SHA-256" },
                privateKey,
                new TextEncoder().encode(signingInput),
            ),
        )
        return `${signingInput}.${b64url(sig)}`
    }
    return { sign, jwk }
}

/** The nonce captured from the authorization URL, echoed into the id_token. */
let capturedNonce: string | undefined

/** Install a fetch mock walking the discovery -> register -> token sequence. */
async function mockOidcFetch() {
    const { sign, jwk } = await makeIdTokenSigner()
    const calls: { url: string; init?: RequestInit }[] = []
    vi.stubGlobal(
        "fetch",
        vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
            const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
            calls.push({ url, init })

            if (url.includes(".well-known/openid-configuration")) {
                return new Response(JSON.stringify(AS_METADATA), {
                    status: 200,
                    headers: { "content-type": "application/json" },
                })
            }
            if (url.endsWith("/jwks")) {
                return new Response(JSON.stringify({ keys: [jwk] }), {
                    status: 200,
                    headers: { "content-type": "application/json" },
                })
            }
            if (url.endsWith("/register")) {
                return new Response(
                    JSON.stringify({
                        client_id: CLIENT_ID,
                        redirect_uris: ["http://localhost:8080/callback.html"],
                        response_types: ["code"],
                        token_endpoint_auth_method: "none",
                        id_token_signed_response_alg: "ES256",
                    }),
                    { status: 201, headers: { "content-type": "application/json" } },
                )
            }
            if (url.endsWith("/token")) {
                const idToken = await sign(capturedNonce!)
                return new Response(
                    JSON.stringify({ access_token: ACCESS_TOKEN, token_type: "DPoP", id_token: idToken }),
                    { status: 200, headers: { "content-type": "application/json" } },
                )
            }
            throw new Error(`unexpected fetch: ${url}`)
        }),
    )
    return calls
}

beforeEach(() => {
    codeCalls = []
    capturedNonce = undefined
})

afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
})

describe("OidcTokenExchange", () => {
    /** Resolve the authorization-code redirect URI from the auth URL's state. */
    const getCode = async (uri: URL): Promise<string> => {
        codeCalls.push({ uri })
        capturedNonce = uri.searchParams.get("nonce")!
        const state = uri.searchParams.get("state")!
        const cb = new URL("http://localhost:8080/callback.html")
        cb.searchParams.set("code", "auth-code")
        cb.searchParams.set("state", state)
        cb.searchParams.set("iss", ISSUER)
        return cb.href
    }

    it("matches every host", async () => {
        const exchange = new OidcTokenExchange(getCode)
        expect(await exchange.matches(new Request("https://anything.example/x"))).toBe(true)
    })

    it("runs discovery -> registration -> code -> DPoP token grant and returns the token", async () => {
        const calls = await mockOidcFetch()
        const exchange = new OidcTokenExchange(getCode)

        const dpopKey = await oauth.generateKeyPair("ES256", { extractable: false })
        const dpop = oauth.DPoP({}, dpopKey)

        const result = await exchange.acquire({
            request: new Request(RESOURCE),
            dpop,
        })

        // It returns the raw token response (binding is the provider's job).
        expect(result.access_token).toBe(ACCESS_TOKEN)

        // The GetCodeCallback was invoked with a PKCE + prompt=none auth URL.
        expect(codeCalls).toHaveLength(1)
        const authUrl = codeCalls[0]!.uri
        expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256")
        expect(authUrl.searchParams.get("prompt")).toBe("none")
        expect(authUrl.searchParams.get("scope")).toBe("openid webid")

        // The token request carried a DPoP proof from the supplied handle.
        const tokenCall = calls.find((c) => c.url.endsWith("/token"))!
        expect(new Headers(tokenCall.init?.headers).get("DPoP")).toBeTruthy()
    })

    it("throws for an unknown issuer host", async () => {
        const exchange = new OidcTokenExchange(getCode)
        const dpopKey = await oauth.generateKeyPair("ES256", { extractable: false })
        const dpop = oauth.DPoP({}, dpopKey)
        await expect(
            exchange.acquire({ request: new Request("https://unknown.example/x"), dpop }),
        ).rejects.toThrow(/Unknown issuer/)
    })
})
