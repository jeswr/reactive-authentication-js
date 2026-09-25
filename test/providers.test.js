import assert from "node:assert/strict"
import { test } from "node:test"
import { createMemoryStore } from "@key-value-kit/storage/memory"
import { CachingIssuerProvider } from "../dist/CachingIssuerProvider.js"
import { CachingAuthorizationServerProvider } from "../dist/CachingAuthorizationServerProvider.js"
import { CachingClientProvider } from "../dist/CachingClientProvider.js"

for (const [Provider, method, args, result, stored, key] of [
    [CachingIssuerProvider, "getIssuer", [new Request("https://pod.example/a")], new URL("https://idp.example"), "https://idp.example/", "https://pod.example/a"],
    [CachingAuthorizationServerProvider, "getAuthorizationServer", [new Request("https://pod.example/a")], { issuer: "https://idp.example" }, { issuer: "https://idp.example" }, "https://pod.example/a"],
    [CachingClientProvider, "getClient", [{ issuer: "https://idp.example" }, "https://app.example/cb", new AbortController().signal], { client_id: "app" }, { client_id: "app" }, "https://idp.example"],
]) {
    test(`${Provider.name}: injected async cache, reconstruction, invalidation, failure retry`, async () => {
        const cache = createMemoryStore()
        let calls = 0
        const original = { async [method]() { calls++; return result } }
        const provider = new Provider(original, cache)
        assert.deepEqual(await provider[method](...args), result)
        assert.deepEqual(await cache.getItem(key), stored)
        assert.deepEqual(await new Provider(original, cache)[method](...args), result)
        assert.equal(calls, 1)
        await cache.removeItem(key)
        await provider[method](...args)
        assert.equal(calls, 2)
        await cache.clear()
        let failed = true
        const retry = new Provider({ async [method]() { if (failed) throw new Error("cancelled"); return result } }, cache)
        await assert.rejects(retry[method](...args), /cancelled/)
        assert.equal(await cache.getItem(key), null)
        failed = false
        assert.deepEqual(await retry[method](...args), result)
    })

    test(`${Provider.name}: accepts a three-method store without clear and propagates read errors`, async () => {
        const { getItem, setItem, removeItem } = createMemoryStore()
        const store = { getItem, setItem, removeItem }
        const original = { async [method]() { return result } }
        assert.deepEqual(await new Provider(original, store)[method](...args), result)
        assert.deepEqual(await store.getItem(key), stored)
        const denied = { ...store, async getItem() { throw new Error("storage denied") } }
        await assert.rejects(new Provider(original, denied)[method](...args), /storage denied/)
    })

    test(`${Provider.name}: default memory cache and awaited write failure`, async () => {
        let calls = 0
        const original = { async [method]() { calls++; return result } }
        const provider = new Provider(original)
        await provider[method](...args)
        await provider[method](...args)
        assert.equal(calls, 1)
        const cache = createMemoryStore()
        cache.setItem = async () => { await Promise.resolve(); throw new Error("quota") }
        await assert.rejects(new Provider(original, cache)[method](...args), /quota/)
    })
}
