// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Samu Lang
// Copyright (c) 2026 Jesse Wright

import type * as oauth from "oauth4webapi"

/**
 * The context handed to a {@link TokenExchange} for a single 401-driven upgrade.
 *
 * The {@link DPoPTokenProvider} owns the DPoP mechanics (keypair, proof
 * generation, nonce tracking, resource binding); it generates the
 * {@link oauth.DPoPHandle} and passes it here so the exchange can attach DPoP
 * proofs to whatever token request it makes. The exchange must therefore not
 * generate its own keypair — sender-constraint continuity (token-endpoint proof
 * and resource proof sharing one key) is the provider's responsibility.
 */
export interface TokenExchangeContext {
    /** The original request that triggered the 401 (target resource + signal). */
    readonly request: Request

    /**
     * The shared DPoP handle to attach to token requests. The same handle is
     * reused by the provider to bind the upgraded resource request, so the
     * token-endpoint proof and the resource proof are signed by one key
     * (RFC 9449). The handle also caches server-issued `DPoP-Nonce`s.
     */
    readonly dpop: oauth.DPoPHandle
}

/**
 * The pluggable token-acquisition strategy for {@link DPoPTokenProvider}.
 *
 * A `TokenExchange` performs *only* the token-acquisition step — discovery,
 * the user ceremony (authorization-code redirect, or WebAuthn assertion), and
 * the token request — returning the raw {@link oauth.TokenEndpointResponse}. It
 * does not touch DPoP keys or the upgraded request: that is the generic
 * provider's job. This is the one varying seam, so new acquisition methods
 * (SAML, device-code, …) are added as new `TokenExchange`s with zero changes to
 * the DPoP-binding mechanics.
 *
 * @see OidcTokenExchange — Solid-OIDC authorization-code flow.
 * @see WebAuthnTokenExchange — redirect-free WebAuthn (passkey) RFC 8693 exchange.
 */
export interface TokenExchange {
    /**
     * Whether this exchange handles the given request's host/issuer. Host
     * selection lives with the exchange (OIDC matches broadly; WebAuthn matches
     * only configured hosts), so {@link DPoPTokenProvider.matches} delegates here
     * and ordering in the providers array still controls precedence.
     */
    matches(request: Request): Promise<boolean>

    /**
     * Acquire a token using the request/OP context and the shared DPoP handle.
     * Returns the processed token-endpoint response; the provider binds its
     * `access_token` to the resource request with a DPoP proof.
     */
    acquire(context: TokenExchangeContext): Promise<oauth.TokenEndpointResponse>
}
