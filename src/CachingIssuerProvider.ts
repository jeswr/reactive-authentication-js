import type { KeyValueStore } from "@key-value-kit/core"
import { createMemoryStore } from "@key-value-kit/storage/memory"
import { IssuerProvider } from "./IssuerProvider.js"

export class CachingIssuerProvider implements IssuerProvider {
    readonly #cache: KeyValueStore<string>
    readonly #original: IssuerProvider

    constructor(original: IssuerProvider, cache: KeyValueStore<string> = createMemoryStore()) {
        this.#cache = cache
        this.#original = original
    }

    async getIssuer(request: Request): Promise<URL> {
        const cached = await this.#cache.getItem(request.url)
        if (cached !== null) {
            return new URL(cached)
        }

        const fresh = await this.#original.getIssuer(request)
        await this.#cache.setItem(request.url, fresh.href)
        return fresh
    }
}
