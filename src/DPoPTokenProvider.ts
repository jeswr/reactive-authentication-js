// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Samu Lang
// Copyright (c) 2026 Jesse Wright

import * as oauth from "oauth4webapi"
import { dpopBoundRequest } from "./dpopBoundRequest.js"
import type { GetCodeCallback } from "./GetCodeCallback.js"
import { OidcTokenExchange } from "./OidcTokenExchange.js"
import type { TokenProvider } from "./TokenProvider.js"
import type { TokenExchange } from "./TokenExchange.js"

/**
 * The generic DPoP-bound {@link TokenProvider} (`spec/ARCHITECTURE.md` §6).
 *
 * It owns the parts that every DPoP-bound login shares — generating the
 * sender-constraining ES256 keypair, attaching the {@link oauth.DPoPHandle} to
 * the token request, and binding the issued token to the resource request — and
 * delegates the *token-acquisition* step to an injected {@link TokenExchange}
 * (the Strategy pattern). On a 401 the orchestrator calls {@link upgrade}, which:
 *
 * 1. generates one DPoP keypair/handle (shared between the token-endpoint proof
 *    and the resource proof, so the binding is consistent — RFC 9449);
 * 2. delegates to `exchange.acquire(...)` to obtain a token; and
 * 3. returns the request upgraded with `Authorization: DPoP <token>` + a
 *    resource-bound `DPoP` proof.
 *
 * Host selection is delegated to {@link TokenExchange.matches}, so ordering in
 * the providers array still controls precedence. The DPoP mechanics are
 * implemented with `oauth4webapi` built-ins (no hand-rolled proofs), so this
 * module lifts cleanly into `@jeswr/solid-reactive-fetch`.
 *
 * @example Solid-OIDC authorization-code login (back-compatible):
 * ```ts
 * new DPoPTokenProvider(getCodeCallback)               // GetCodeCallback overload
 * new DPoPTokenProvider(new OidcTokenExchange(getCode)) // explicit strategy
 * ```
 *
 * @example Redirect-free WebAuthn re-authentication:
 * ```ts
 * new DPoPTokenProvider(new WebAuthnTokenExchange(config))
 * // or the convenience subclass:
 * new WebAuthnTokenProvider(config)
 * ```
 */
export class DPoPTokenProvider implements TokenProvider {
    readonly #exchange: TokenExchange

    /**
     * @param exchange The token-acquisition strategy, or — for backward
     * compatibility with the original `DPoPTokenProvider(getCode)` constructor —
     * a {@link GetCodeCallback}, which is wrapped in an {@link OidcTokenExchange}.
     */
    constructor(exchange: TokenExchange | GetCodeCallback) {
        this.#exchange = isTokenExchange(exchange) ? exchange : new OidcTokenExchange(exchange)
    }

    /** Construct the OIDC authorization-code provider from a {@link GetCodeCallback}. */
    static oidc(getCodeCallback: GetCodeCallback): DPoPTokenProvider {
        return new DPoPTokenProvider(new OidcTokenExchange(getCodeCallback))
    }

    /** Delegate host selection to the injected exchange. */
    async matches(request: Request): Promise<boolean> {
        return this.#exchange.matches(request)
    }

    async upgrade(request: Request): Promise<Request> {
        // One keypair/handle for the whole upgrade: the token-endpoint proof and
        // the resource proof are signed by the same key (RFC 9449), and the
        // handle caches any server-issued `DPoP-Nonce`.
        // TODO: Align with dpop_signing_alg_values_supported and fallback.
        const dpopKey = await oauth.generateKeyPair("ES256", { extractable: false })
        const dpop = oauth.DPoP({}, dpopKey)

        const tokenResult = await this.#exchange.acquire({ request, dpop })

        return dpopBoundRequest(request, tokenResult.access_token, dpop)
    }
}

/** Duck-type the {@link TokenExchange} strategy apart from a {@link GetCodeCallback}. */
function isTokenExchange(value: TokenExchange | GetCodeCallback): value is TokenExchange {
    return typeof (value as TokenExchange).acquire === "function"
}
