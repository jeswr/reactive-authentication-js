import type * as oauth from "oauth4webapi"
import { withExpiry } from "@key-value-kit/core"
import type { ClearableStore, ExpiringValue } from "@key-value-kit/core"
import { createIndexedDbStore } from "@key-value-kit/storage/indexeddb"
import { createMemoryStore } from "@key-value-kit/storage/memory"
import type { DPoPTokenCacheEntry } from "./DPoPTokenProvider.js"

export interface ProviderCaches {
    issuer: ClearableStore<string>
    authorizationServer: ClearableStore<oauth.AuthorizationServer>
    client: ClearableStore<oauth.Client>
    token: ClearableStore<DPoPTokenCacheEntry>
}

/**
 * Explicit browser policy: public metadata in IndexedDB for one hour by default;
 * client registrations and credentials in memory. Namespace must isolate app/account
 * contexts. Storage failures reject without silently switching backends.
 */
export function createBrowserCaches(namespace: string, metadataMaxAgeMs = 60 * 60 * 1000): ProviderCaches {
    if (namespace.length === 0) throw new TypeError("A cache namespace is required")
    // v2 uses Key Value Kit's database layout; prototype caches are not migrated.
    return {
        issuer: withExpiry(createIndexedDbStore<ExpiringValue<string>>({
            namespace: `${namespace}:v2:issuer`,
        }), { ttlMs: metadataMaxAgeMs }),
        authorizationServer: withExpiry(createIndexedDbStore<ExpiringValue<oauth.AuthorizationServer>>({
            namespace: `${namespace}:v2:authorization-server`,
        }), { ttlMs: metadataMaxAgeMs }),
        client: createMemoryStore(),
        token: createMemoryStore(),
    }
}
