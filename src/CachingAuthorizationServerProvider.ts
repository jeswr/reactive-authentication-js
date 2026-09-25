import type { KeyValueStore } from "@key-value-kit/core"
import { createMemoryStore } from "@key-value-kit/storage/memory"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #cache: KeyValueStore<oauth.AuthorizationServer>
    readonly #original: AuthorizationServerProvider

    constructor(original: AuthorizationServerProvider, cache: KeyValueStore<oauth.AuthorizationServer> = createMemoryStore()) {
        this.#cache = cache
        this.#original = original
    }

    async getAuthorizationServer(request: Request): Promise<oauth.AuthorizationServer> {
        const cached = await this.#cache.getItem(request.url)
        if (cached !== null) {
            return cached
        }

        const fresh = await this.#original.getAuthorizationServer(request)
        await this.#cache.setItem(request.url, fresh)
        return fresh
    }
}
