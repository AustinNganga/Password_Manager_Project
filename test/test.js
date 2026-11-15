"use strict";
const expect = require("expect.js");
const { Keychain } = require("../password-manager");

// The Keychain throws plain strings, so compare String(e).
async function fails(p, re) {
  try { await p; } catch (e) { expect(String(e)).to.match(re); return; }
  throw new Error("expected the promise to reject");
}
const PW = "correct horse battery";

describe("Keychain", function () {
  this.timeout(20000);

  it("stores and retrieves a password", async () => {
    const kc = await Keychain.init(PW);
    await kc.set("example.com", "hunter2");
    expect(await kc.get("example.com")).to.be("hunter2");
  });

  it("returns null for unknown sites", async () => {
    const kc = await Keychain.init(PW);
    expect(await kc.get("nope.com")).to.be(null);
  });

  it("overwrites an existing site", async () => {
    const kc = await Keychain.init(PW);
    await kc.set("a.com", "one"); await kc.set("a.com", "two");
    expect(await kc.get("a.com")).to.be("two");
  });

  it("removes records", async () => {
    const kc = await Keychain.init(PW);
    await kc.set("a.com", "x");
    expect(await kc.remove("a.com")).to.be(true);
    expect(await kc.remove("a.com")).to.be(false);
    expect(await kc.get("a.com")).to.be(null);
  });

  it("survives dump and load with the right password and checksum", async () => {
    const kc = await Keychain.init(PW);
    await kc.set("a.com", "secret-a"); await kc.set("b.com", "secret-b");
    const [repr, sum] = await kc.dump();
    const kc2 = await Keychain.load(PW, repr, sum);
    expect(await kc2.get("a.com")).to.be("secret-a");
    expect(await kc2.get("b.com")).to.be("secret-b");
  });

  it("rejects the wrong master password", async () => {
    const kc = await Keychain.init(PW);
    await kc.set("a.com", "x");
    const [repr] = await kc.dump();
    await fails(Keychain.load("wrong password", repr), /./);
  });

  it("does not leak password length through ciphertext size", async () => {
    const kc = await Keychain.init(PW);
    await kc.set("a.com", "x"); await kc.set("b.com", "y".repeat(60));
    const kvs = JSON.parse((await kc.dump())[0]).kvs;
    const sizes = new Set(Object.values(kvs).map(r => Buffer.from(r.ct, "base64").length));
    expect(sizes.size).to.be(1);
  });

  it("detects swapped records (swap attack)", async () => {
    const kc = await Keychain.init(PW);
    await kc.set("a.com", "secret-a"); await kc.set("b.com", "secret-b");
    const t = JSON.parse((await kc.dump())[0]), [x, y] = Object.keys(t.kvs);
    [t.kvs[x], t.kvs[y]] = [t.kvs[y], t.kvs[x]];
    const bad = await Keychain.load(PW, JSON.stringify(t));
    await fails(bad.get("a.com"), /./);
    await fails(bad.get("b.com"), /./);
  });

  it("detects rollback to an older version", async () => {
    const kc = await Keychain.init(PW);
    await kc.set("a.com", "v1");
    const [oldRepr] = await kc.dump();
    await kc.set("a.com", "v2");
    const [, newSum] = await kc.dump();
    await fails(Keychain.load(PW, oldRepr, newSum), /Tampering/);
  });

  it("detects a wrong trusted checksum", async () => {
    const kc = await Keychain.init(PW);
    await kc.set("a.com", "v1");
    const [, oldSum] = await kc.dump();
    await kc.set("a.com", "v2");
    const [newRepr] = await kc.dump();
    await fails(Keychain.load(PW, newRepr, oldSum), /Tampering/);
  });
});
