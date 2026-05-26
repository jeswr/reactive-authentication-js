// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Samu Lang
// Copyright (c) 2026 Jesse Wright

import { describe, it, expect, vi } from "vitest"
import * as oauth from "oauth4webapi"
import { DPoPTokenProvider } from "./DPoPTokenProvider.js"
import { OidcTokenExchange } from "./OidcTokenExchange.js"
import { WebAuthnTokenProvider } from "./WebAuthnTokenProvider.js"
import type { TokenExchange, TokenExchangeContext } from "./TokenExchange.js"

const POD = "https://pod.example"
const ACCESS_TOKEN = "the.access.token"

/** Decode the `htu` claim from a DPoP proof JWT (header.payload.sig). */
function dpopHtu(proof: string): string {
    const payload = proof.split(".")[1]!
    const json = Buffer.from(payload, "base64url").toString("utf8")
    return (JSON.parse(json) as { htu: string }).htu
}

/**
 * A minimal {@link TokenExchange} that records the context it is given and
 * returns a fixed token result. It does NOT generate its own DPoP key — the
 * provider must supply the handle, which we capture to assert the binding.
 */
class StubExchange implements TokenExchange {
    captured?: TokenExchangeContext
    constructor(
        private readonly tokenType: string = "dpop",
        private readonly hosts: string[] = ["pod.example"],
    ) {}

    async matches(request: Request): Promise<boolean> {
        return this.hosts.includes(new URL(request.url).host)
    }

    async acquire(context: TokenExchangeContext): Promise<oauth.TokenEndpointResponse> {
        this.captured = context
        return {
            access_token: ACCESS_TOKEN,
            token_type: this.tokenType as oauth.TokenEndpointResponse["token_type"],
        }
    }
}

describe("DPoPTokenProvider (generic)", () => {
    it("delegates host matching to the injected exchange", async () => {
        const provider = new DPoPTokenProvider(new StubExchange("dpop", ["pod.example"]))
        expect(await provider.matches(new Request(`${POD}/r`))).toBe(true)
        expect(await provider.matches(new Request("https://other.example/r"))).toBe(false)
    })

    it("generates a DPoP handle, passes it to acquire, and binds the resource request", async () => {
        const exchange = new StubExchange()
        const provider = new DPoPTokenProvider(exchange)

        const upgraded = await provider.upgrade(new Request(`${POD}/resource`))

        // The provider owns DPoP: the exchange received a handle + the request.
        expect(exchange.captured?.dpop).toBeDefined()
        expect(exchange.captured?.request.url).toBe(`${POD}/resource`)

        // The upgraded request carries the DPoP-bound token.
        expect(upgraded.headers.get("Authorization")).toBe(`DPoP ${ACCESS_TOKEN}`)
        expect(upgraded.headers.get("DPoP")).toBeTruthy()
        expect(upgraded.url).toBe(`${POD}/resource`)
    })

    it("binds the resource proof with a query/fragment-stripped htu (RFC 9449 §4.2)", async () => {
        const provider = new DPoPTokenProvider(new StubExchange())
        const upgraded = await provider.upgrade(new Request(`${POD}/resource?a=1#f`))
        expect(dpopHtu(upgraded.headers.get("DPoP")!)).toBe(`${POD}/resource`)
    })

    it("reuses one DPoP handle across the exchange and the resource binding", async () => {
        const exchange = new StubExchange()
        const provider = new DPoPTokenProvider(exchange)

        // Spy on the handle the exchange receives; the resource binding must use
        // the same instance (so the token-endpoint and resource proofs share a key).
        const upgrade1 = await provider.upgrade(new Request(`${POD}/a`))
        const handle1 = exchange.captured!.dpop
        const upgrade2 = await provider.upgrade(new Request(`${POD}/b`))
        const handle2 = exchange.captured!.dpop

        // Distinct upgrades get distinct handles (fresh keypair each time).
        expect(handle1).not.toBe(handle2)
        // Each produced a resource-bound proof.
        expect(upgrade1.headers.get("DPoP")).toBeTruthy()
        expect(upgrade2.headers.get("DPoP")).toBeTruthy()
    })

    describe("backward-compatible OIDC construction", () => {
        it("wraps a GetCodeCallback in an OidcTokenExchange (constructor overload)", async () => {
            const getCode = vi.fn(async () => "https://app/callback?code=x")
            const provider = new DPoPTokenProvider(getCode)
            // The OIDC exchange matches all hosts.
            expect(await provider.matches(new Request(`${POD}/r`))).toBe(true)
        })

        it("exposes the DPoPTokenProvider.oidc(getCode) factory", async () => {
            const getCode = vi.fn(async () => "https://app/callback?code=x")
            const provider = DPoPTokenProvider.oidc(getCode)
            expect(provider).toBeInstanceOf(DPoPTokenProvider)
            expect(await provider.matches(new Request(`${POD}/r`))).toBe(true)
        })

        it("accepts an explicit OidcTokenExchange", async () => {
            const getCode = vi.fn(async () => "https://app/callback?code=x")
            const provider = new DPoPTokenProvider(new OidcTokenExchange(getCode))
            expect(await provider.matches(new Request(`${POD}/r`))).toBe(true)
        })
    })

    describe("WebAuthnTokenProvider back-compat subclass", () => {
        it("is a DPoPTokenProvider configured with a WebAuthnTokenExchange", () => {
            const provider = new WebAuthnTokenProvider({
                "pod.example": { issuer: "https://op.example" },
            })
            expect(provider).toBeInstanceOf(DPoPTokenProvider)
        })

        it("matches only configured hosts (delegated to the WebAuthn exchange)", async () => {
            const provider = new WebAuthnTokenProvider({
                "pod.example": { issuer: "https://op.example" },
            })
            expect(await provider.matches(new Request(`${POD}/r`))).toBe(true)
            expect(await provider.matches(new Request("https://other.example/r"))).toBe(false)
        })
    })
})
