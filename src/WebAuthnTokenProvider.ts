// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Samu Lang
// Copyright (c) 2026 Jesse Wright

import * as oauth from "oauth4webapi"
import { startAuthentication } from "@simplewebauthn/browser"
import {
    TOKEN_EXCHANGE_GRANT_TYPE,
    WEBAUTHN_ASSERTION_TOKEN_TYPE,
    BUNDLE_VERSION,
    encodeAssertionBundle,
} from "@jeswr/solid-webauthn-protocol"
import type {
    AssertionOptions,
    AssertionBundle,
} from "@jeswr/solid-webauthn-protocol"
import { dpopBoundRequest } from "./dpopBoundRequest.js"
import type { TokenProvider } from "./TokenProvider.js"

/**
 * Per-OpenID-Provider configuration for {@link WebAuthnTokenProvider}.
 *
 * The provider matches a request to an OP by host (see {@link WebAuthnConfig}),
 * fetches a challenge from {@link assertionOptionsEndpoint}, relays a WebAuthn
 * assertion to {@link tokenEndpoint}, and binds the issued token with DPoP.
 */
export interface WebAuthnIssuerConfig {
    /** The OP issuer URL (e.g. `https://op.example`). */
    issuer: string | URL

    /**
     * The conventional WebAuthn assertion-options endpoint that issues the
     * single-use challenge (`spec/ARCHITECTURE.md` §6.2). Defaults to
     * `<issuer>/.oidc/webauthn/assertion-options` when omitted.
     */
    assertionOptionsEndpoint?: string | URL

    /**
     * HTTP method for the assertion-options request. Issuing a single-use
     * challenge is a state-changing, non-cacheable operation, so this defaults
     * to `POST` (`spec/ARCHITECTURE.md` §6.2, §8.3). Set to `"GET"` for OPs that
     * expose the challenge as a safe read.
     */
    assertionOptionsMethod?: "GET" | "POST"

    /**
     * The token endpoint for the RFC 8693 token exchange. Defaults to the
     * issuer's OIDC-discovered `token_endpoint`, falling back to
     * `<issuer>/.oidc/token`.
     */
    tokenEndpoint?: string | URL

    /**
     * The application's Solid-OIDC **Client ID Document URI** — the public
     * `client_id` the OP authenticates at the token endpoint (the app is a
     * public client, `token_endpoint_auth_method: none`). It is sent in the
     * RFC 8693 token-exchange body so the OP can (a) dereference the document to
     * resolve the app's allowed origins (`spec/ARCHITECTURE.md` §8.2) and
     * (b) bind the issued token's `client_id`/`azp` claim. Defaults to the app's
     * own origin (`<page-origin>/`) when omitted, but a Solid-OIDC client SHOULD
     * set its Client ID Document URI so the credential's ⟨WebID, ClientID⟩ binding
     * is the dereferenceable document, not a bare origin.
     */
    clientId?: string | URL
}

/**
 * Maps a request host to a {@link WebAuthnIssuerConfig}. The provider is
 * selected (via {@link WebAuthnTokenProvider.matches}) only for hosts present
 * here, so it can sit alongside `DPoPTokenProvider`/`BearerTokenProvider` in the
 * providers array — ordering controls precedence, first match wins.
 */
export type WebAuthnConfig = Record<string, WebAuthnIssuerConfig>

const DEFAULT_OPTIONS_PATH = "/.oidc/webauthn/assertion-options"
const DEFAULT_TOKEN_PATH = "/.oidc/token"

/** No-op client authentication for a public client with no `client_id`. */
const noClientAuth: oauth.ClientAuth = () => {}

/**
 * A {@link TokenProvider} that performs redirect-free Solid-OIDC re-authentication
 * with a WebAuthn (passkey) assertion (`spec/ARCHITECTURE.md` §6.2).
 *
 * On a 401, the orchestrator calls {@link upgrade}, which:
 * 1. resolves the OP for the target request;
 * 2. `POST`s the OP assertion-options endpoint for a single-use challenge;
 * 3. runs the WebAuthn `get()` ceremony (`navigator.credentials.get`, via
 *    SimpleWebAuthn's `startAuthentication`) — the app is the Relying Party, so
 *    the assertion's `clientDataJSON.origin` unspoofably attests the app;
 * 4. encodes the assertion as the versioned bundle `subject_token`;
 * 5. exchanges it at the token endpoint (RFC 8693) with a DPoP proof; and
 * 6. returns the request upgraded with `Authorization: DPoP <token>` + a
 *    resource-bound `DPoP` proof.
 *
 * DPoP (proof generation, nonce tracking, `htu` computation) and the RFC 8693
 * exchange are delegated to `oauth4webapi` built-ins — no hand-rolled proofs.
 *
 * No orchestrator edits are required, so this module lifts cleanly into
 * `@jeswr/solid-reactive-fetch`.
 */
export class WebAuthnTokenProvider implements TokenProvider {
    readonly #config: WebAuthnConfig

    constructor(config: WebAuthnConfig) {
        this.#config = config
    }

    /** Select this provider when the request host has WebAuthn config. */
    async matches(request: Request): Promise<boolean> {
        return this.#configFor(request) !== undefined
    }

    async upgrade(request: Request): Promise<Request> {
        const issuerConfig = this.#configFor(request)
        if (issuerConfig === undefined) {
            throw new Error(`No WebAuthn configuration for ${request.url}`)
        }

        // (a) Discover the OP — resolve the token endpoint from OIDC discovery
        // (with a conventional fallback); the assertion-options endpoint is a
        // conventional (non-discovery) endpoint per `decisions/0004`.
        const issuer = new URL(issuerConfig.issuer)
        const tokenEndpoint = await this.#resolveTokenEndpoint(issuer, issuerConfig)
        const optionsEndpoint = this.#resolveOptionsEndpoint(issuer, issuerConfig)

        // (b) Fetch a single-use challenge (POST by default — issuing the
        // challenge is state-changing, `spec/ARCHITECTURE.md` §6.2/§8.3).
        const optionsResponse = await fetch(optionsEndpoint, {
            method: issuerConfig.assertionOptionsMethod ?? "POST",
            headers: { accept: "application/json" },
            signal: request.signal,
        })
        if (!optionsResponse.ok) {
            throw new Error(
                `Assertion-options request failed: ${optionsResponse.status} ${optionsResponse.statusText}`,
            )
        }
        const optionsJSON = (await optionsResponse.json()) as AssertionOptions

        // (c) Run the WebAuthn assertion ceremony (navigator.credentials.get).
        const credential = await startAuthentication({ optionsJSON })

        // (d) Build and encode the versioned assertion bundle (`subject_token`).
        const bundle: AssertionBundle = { version: BUNDLE_VERSION, credential }
        const subjectToken = encodeAssertionBundle(bundle)

        // (e) DPoP-bound RFC 8693 token exchange. The `oauth4webapi` DPoP handle
        // attaches proofs and tracks server-issued nonces; `isDPoPNonceError`
        // drives the single retry (RFC 9449 §8).
        const dpopKey = await oauth.generateKeyPair("ES256", { extractable: false })
        const dpop = oauth.DPoP({}, dpopKey)
        const accessToken = await this.#exchange(
            issuer,
            tokenEndpoint,
            issuerConfig,
            subjectToken,
            dpop,
            request.signal,
        )

        // (f) Return the request upgraded with a resource-bound DPoP proof
        // (the same DPoP handle computes `htu` and `ath`).
        return dpopBoundRequest(request, accessToken, dpop)
    }

    /**
     * RFC 8693 token exchange at the token endpoint with a DPoP proof, retrying
     * once on a `use_dpop_nonce` challenge (RFC 9449 §8). The DPoP handle has
     * already cached the server nonce by the time {@link oauth.isDPoPNonceError}
     * reports the need to retry.
     */
    async #exchange(
        issuer: URL,
        tokenEndpoint: URL,
        config: WebAuthnIssuerConfig,
        subjectToken: string,
        dpop: oauth.DPoPHandle,
        signal: AbortSignal,
    ): Promise<string> {
        const as: oauth.AuthorizationServer = {
            issuer: issuer.href,
            token_endpoint: tokenEndpoint.href,
        }
        // The app is a public client (`token_endpoint_auth_method: none`); the
        // OP authenticates it solely by dereferencing this Client ID Document URI
        // (Solid-OIDC). `None()` sends it as the `client_id` body parameter;
        // without it a Solid OP rejects with `invalid_request - no client
        // authentication mechanism provided`. With no `client_id` (non-browser,
        // unconfigured) the OP must accept an unauthenticated public client.
        const clientId = this.#clientId(config)
        // `assertClient` requires a non-empty `client_id`; with no real client
        // (non-browser, unconfigured) we satisfy it with a placeholder and a
        // no-op auth so nothing is sent. `None()` sends the real `client_id`.
        const client: oauth.Client = { client_id: clientId?.href ?? as.issuer }
        const clientAuth = clientId !== undefined ? oauth.None() : noClientAuth

        const parameters = new URLSearchParams()
        parameters.set("subject_token", subjectToken)
        parameters.set("subject_token_type", WEBAUTHN_ASSERTION_TOKEN_TYPE)

        const exchangeOnce = () =>
            oauth.genericTokenEndpointRequest(
                as,
                client,
                clientAuth,
                TOKEN_EXCHANGE_GRANT_TYPE,
                parameters,
                { DPoP: dpop, signal },
            )

        let response = await exchangeOnce()
        try {
            return await this.#processTokenResponse(as, client, response)
        } catch (error) {
            if (!oauth.isDPoPNonceError(error)) {
                throw error
            }
            response = await exchangeOnce()
            return this.#processTokenResponse(as, client, response)
        }
    }

    async #processTokenResponse(
        as: oauth.AuthorizationServer,
        client: oauth.Client,
        response: Response,
    ): Promise<string> {
        const result = await oauth.processGenericTokenEndpointResponse(as, client, response)
        // This flow always sender-constrains with DPoP; a Bearer token would be
        // bound with a (malformed) `Authorization: DPoP` header downstream, so
        // reject it here. `token_type` is normalised to lowercase by oauth4webapi.
        if (result.token_type !== "dpop") {
            throw new Error(
                `Token exchange returned a non-DPoP token (token_type: ${result.token_type})`,
            )
        }
        return result.access_token
    }

    async #resolveTokenEndpoint(issuer: URL, config: WebAuthnIssuerConfig): Promise<URL> {
        if (config.tokenEndpoint !== undefined) {
            return new URL(config.tokenEndpoint)
        }
        try {
            const discoveryResponse = await oauth.discoveryRequest(issuer)
            const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)
            if (authorizationServer.token_endpoint !== undefined) {
                return new URL(authorizationServer.token_endpoint)
            }
        } catch {
            // Fall through to the conventional path.
        }
        return new URL(DEFAULT_TOKEN_PATH, issuer)
    }

    #resolveOptionsEndpoint(issuer: URL, config: WebAuthnIssuerConfig): URL {
        return config.assertionOptionsEndpoint !== undefined
            ? new URL(config.assertionOptionsEndpoint)
            : new URL(DEFAULT_OPTIONS_PATH, issuer)
    }

    /**
     * The `client_id` to authenticate as: the configured Client ID Document URI,
     * else the app's own origin root (a valid bare-origin Solid-OIDC client_id)
     * when running in a browser. Returns `undefined` only outside a browser with
     * no configured `clientId` — in which case the OP must accept an
     * unauthenticated public client, or the caller should configure `clientId`.
     */
    #clientId(config: WebAuthnIssuerConfig): URL | undefined {
        if (config.clientId !== undefined) {
            return new URL(config.clientId)
        }
        if (typeof location !== "undefined" && location.origin && location.origin !== "null") {
            return new URL("/", location.origin)
        }
        return undefined
    }

    /** First config whose host is the substring/host match for the request. */
    #configFor(request: Request): WebAuthnIssuerConfig | undefined {
        const host = new URL(request.url).host
        return this.#config[host]
    }
}
