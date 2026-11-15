"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

// Fixed size of a padded password block: 2-byte length prefix + 64 chars * 4 bytes (max UTF-8 size)
const PADDED_LENGTH = 2 + MAX_PASSWORD_LENGTH * 4;
const CANARY_PLAINTEXT = "KEYCHAIN-CANARY-v1";
const CANARY_AAD = "keychain-canary";
const IV_LENGTH = 12;

/********* Implementation ********/

/*
 * CONTRACT (shared by all three students)
 *   this.data    = { salt, canary, kvs }   <- PUBLIC, this is exactly what dump() serializes
 *                    salt   : Base64 string (16 random bytes, stored in the clear)
 *                    canary : Base64 string (iv || AES-GCM ciphertext of a known value)
 *                    kvs    : { Base64(HMAC(hmacKey, domain)) : Base64(iv || ciphertext) }
 *   this.secrets = { hmacKey, aesKey }     <- PRIVATE CryptoKeys, never serialized
 */
class Keychain {

  /******************************************************************
   *  STUDENT 1 PART: constructor, init, key derivation, padding, canary
   *  (reconstructed from the documented contract -- replace with
   *   Student 1's real code if it differs)
   ******************************************************************/

  constructor({ salt, canary, kvs, hmacKey, aesKey }) {
    this.data = { salt, canary, kvs };
    this.secrets = { hmacKey, aesKey };
  };

  // Exactly ONE PBKDF2 call. PBKDF2 -> master key k (HMAC key) -> two sub-keys via HMAC(k, label).
  static async deriveKeys(password, salt) {
    const pwKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);
    const masterKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      pwKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]
    );
    const hmacRaw = await subtle.sign("HMAC", masterKey, stringToBuffer("hmac-key-for-domain-names"));
    const aesRaw = await subtle.sign("HMAC", masterKey, stringToBuffer("aes-gcm-key-for-passwords"));
    const hmacKey = await subtle.importKey("raw", hmacRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const aesKey = await subtle.importKey("raw", aesRaw, "AES-GCM", false, ["encrypt", "decrypt"]);
    return { hmacKey, aesKey };
  }

  static padPassword(str) {
    if (typeof str !== "string" || str.length > MAX_PASSWORD_LENGTH) {
      throw "Password must be a string of at most " + MAX_PASSWORD_LENGTH + " characters";
    }
    const bytes = stringToBuffer(str);
    const block = new Uint8Array(PADDED_LENGTH); // zero filled
    block[0] = (bytes.length >> 8) & 0xff;
    block[1] = bytes.length & 0xff;
    block.set(bytes, 2);
    return block;
  }

  static unpadPassword(block) {
    const len = (block[0] << 8) | block[1];
    if (len > PADDED_LENGTH - 2) throw "Corrupted record: bad length";
    return bufferToString(block.slice(2, 2 + len));
  }

  static async createCanary(aesKey) {
    const iv = getRandomBytes(IV_LENGTH);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(CANARY_AAD) },
      aesKey, stringToBuffer(CANARY_PLAINTEXT));
    return encodeBuffer(Buffer.concat([Buffer.from(iv), Buffer.from(ct)]));
  }

  // Throws if the key is wrong or the canary was tampered with.
  static async verifyCanary(aesKey, canary) {
    const raw = decodeBuffer(canary);
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: raw.subarray(0, IV_LENGTH), additionalData: stringToBuffer(CANARY_AAD) },
      aesKey, raw.subarray(IV_LENGTH));
    if (bufferToString(pt) !== CANARY_PLAINTEXT) throw "Canary mismatch";
    return true;
  }

  static async init(password) {
    const salt = getRandomBytes(16);
    const { hmacKey, aesKey } = await Keychain.deriveKeys(password, salt);
    const canary = await Keychain.createCanary(aesKey);
    return new Keychain({ salt: encodeBuffer(salt), canary: canary, kvs: {}, hmacKey: hmacKey, aesKey: aesKey });
  }

  /******************************************************************
   *  STUDENT 2 PART: set, get, remove
   *  (stand-in written from the contract so that Student 3's part can
   *   be tested -- replace with Student 2's real code)
   ******************************************************************/

  // Base64(HMAC(hmacKey, name)) -- the key under which a domain is stored
  async _domainKey(name) {
    const tag = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    return encodeBuffer(tag);
  }

  async set(name, value) {
    const key = await this._domainKey(name);
    const iv = getRandomBytes(IV_LENGTH); // fresh random IV every time
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: decodeBuffer(key) }, // tag bound as AAD = swap defense
      this.secrets.aesKey, Keychain.padPassword(value));
    this.data.kvs[key] = encodeBuffer(Buffer.concat([Buffer.from(iv), Buffer.from(ct)]));
  };

  async get(name) {
    const key = await this._domainKey(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, key)) return null;
    const raw = decodeBuffer(this.data.kvs[key]);
    let pt;
    try {
      pt = await subtle.decrypt(
        { name: "AES-GCM", iv: raw.subarray(0, IV_LENGTH), additionalData: decodeBuffer(key) },
        this.secrets.aesKey, raw.subarray(IV_LENGTH));
    } catch (e) {
      throw "Tampering detected: record failed authentication";
    }
    return Keychain.unpadPassword(new Uint8Array(pt));
  };

  async remove(name) {
    const key = await this._domainKey(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, key)) return false;
    delete this.data.kvs[key];
    return true;
  };

  /******************************************************************
   *  STUDENT 3 PART: dump, load  (persistence + integrity)
   ******************************************************************/

  /**
    * Returns [ JSON string of this.data, Base64(SHA-256(that exact string)) ].
    * The second element goes to trusted storage and is the rollback defense.
    * Run-time: O(n) (JSON.stringify + one hash over the n records).
    */
  async dump() {
    const repr = JSON.stringify(this.data);
    const checksum = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)));
    return [repr, checksum];
  };

  /**
    * Loads a keychain from the output of dump().
    *  1. If trustedDataCheck is given, hash the exact repr string and compare (rollback defense).
    *  2. Parse JSON and do a basic structure check.
    *  3. Re-derive keys from the password + stored salt (a single PBKDF2 call).
    *  4. Verify the password by decrypting the canary (wrong password => GCM failure => throw).
    *  5. Build the Keychain from the parsed kvs field.
    * Run-time: O(n) (hash + JSON.parse); the key derivation is O(1).
    */
  static async load(password, repr, trustedDataCheck) {
    // 1. Rollback / tamper check against trusted storage (only if provided)
    if (trustedDataCheck !== undefined && trustedDataCheck !== null) {
      const actual = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)));
      if (actual !== trustedDataCheck) {
        throw "Tampering detected: checksum does not match trusted data (modified or rolled-back database)";
      }
    }

    // 2. Parse + structure check
    let parsed;
    try {
      parsed = JSON.parse(repr);
    } catch (e) {
      throw "Invalid keychain representation";
    }
    if (parsed === null || typeof parsed !== "object" ||
        typeof parsed.salt !== "string" || typeof parsed.canary !== "string" ||
        parsed.kvs === null || typeof parsed.kvs !== "object" || Array.isArray(parsed.kvs)) {
      throw "Invalid keychain representation";
    }

    // 3. Re-derive keys (exactly ONE PBKDF2 call)
    const { hmacKey, aesKey } = await Keychain.deriveKeys(password, decodeBuffer(parsed.salt));

    // 4. Password verification via the canary
    let ok;
    try {
      ok = await Keychain.verifyCanary(aesKey, parsed.canary);
    } catch (e) {
      ok = false;
    }
    if (ok === false) {
      throw "Invalid master password (or the keychain was tampered with)";
    }

    // 5. Restore. We use parsed.kvs, so edits to the kvs field are reflected in the object.
    return new Keychain({ salt: parsed.salt, canary: parsed.canary, kvs: parsed.kvs, hmacKey: hmacKey, aesKey: aesKey });
  };
};

module.exports = { Keychain }