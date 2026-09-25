import assert from "node:assert/strict"
import { test } from "node:test"
import "fake-indexeddb/auto"
import { createBrowserCaches } from "../dist/createBrowserCaches.js"

test("browser preset persists only metadata, isolates accounts, and expires metadata", async t => {
    let now = 1000
    t.mock.method(Date, "now", () => now)
    const caches = createBrowserCaches("my-app/account", 100)
    const other = createBrowserCaches("my-app/other-account", 100)
    await caches.issuer.setItem("resource", "https://idp.example")
    await caches.authorizationServer.setItem("resource", { issuer: "https://idp.example" })
    await caches.client.setItem("issuer", { client_id: "private-client" })
    await caches.token.setItem("resource", { secret: "memory only" })
    await other.issuer.setItem("resource", "https://other.example")
    const restored = createBrowserCaches("my-app/account", 100)
    assert.equal(await restored.issuer.getItem("resource"), "https://idp.example")
    assert.deepEqual(await restored.authorizationServer.getItem("resource"), { issuer: "https://idp.example" })
    assert.equal(await restored.client.getItem("issuer"), null)
    assert.equal(await restored.token.getItem("resource"), null)
    now = 1099
    assert.notEqual(await restored.issuer.getItem("resource"), null)
    now = 1100
    assert.equal(await restored.issuer.getItem("resource"), null)
    assert.equal(await restored.authorizationServer.getItem("resource"), null)
    await other.issuer.setItem("resource", "https://other.example")
    await restored.issuer.clear()
    assert.equal(await other.issuer.getItem("resource"), "https://other.example")
    await restored.authorizationServer.clear()
    await other.issuer.clear()
})

test("browser preset validates namespace and metadata lifetime", () => {
    assert.throws(() => createBrowserCaches(""), TypeError)
    for (const age of [0, -1, NaN, Infinity]) {
        assert.throws(() => createBrowserCaches("invalid-ttl", age), RangeError)
    }
})
