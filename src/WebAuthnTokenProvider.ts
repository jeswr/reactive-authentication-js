// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Samu Lang
// Copyright (c) 2026 Jesse Wright

import { DPoPTokenProvider } from "./DPoPTokenProvider.js"
import { WebAuthnTokenExchange } from "./WebAuthnTokenExchange.js"
import type { WebAuthnConfig } from "./WebAuthnTokenExchange.js"

// Re-export the config surface so existing imports
// (`import { WebAuthnTokenProvider, WebAuthnConfig } from "..."`) keep resolving.
export type { WebAuthnConfig, WebAuthnIssuerConfig } from "./WebAuthnTokenExchange.js"

/**
 * Redirect-free Solid-OIDC re-authentication with a WebAuthn (passkey) assertion
 * (`spec/ARCHITECTURE.md` §6.2).
 *
 * A thin convenience over the generic {@link DPoPTokenProvider}: it is exactly
 * `new DPoPTokenProvider(new WebAuthnTokenExchange(config))`. The DPoP-binding
 * mechanics live in the provider; the WebAuthn assertion-options → ceremony →
 * RFC 8693 exchange lives in {@link WebAuthnTokenExchange}. Kept as a named class
 * so existing `new WebAuthnTokenProvider(config)` callers are unaffected.
 */
export class WebAuthnTokenProvider extends DPoPTokenProvider {
    constructor(config: WebAuthnConfig) {
        super(new WebAuthnTokenExchange(config))
    }
}
