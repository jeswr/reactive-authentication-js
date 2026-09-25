import type { KeyValueStore } from "@key-value-kit/core"
import { createMemoryStore } from "@key-value-kit/storage/memory"
import type { ClientProvider } from "./ClientProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingClientProvider implements ClientProvider {
    readonly #cache: KeyValueStore<oauth.Client>
    readonly #original: ClientProvider

    constructor(original: ClientProvider, cache: KeyValueStore<oauth.Client> = createMemoryStore()) {
        this.#cache = cache
        this.#original = original
    }

    async getClient(as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal): Promise<oauth.Client> {
        const cached = await this.#cache.getItem(as.issuer)
        if (cached !== null) {
            return cached
        }

        const fresh = await this.#original.getClient(as, redirectUri, signal)
        await this.#cache.setItem(as.issuer, fresh)
        return fresh
    }
}
