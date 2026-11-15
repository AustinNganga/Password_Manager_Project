"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

// --- Additional constants (Student 1) ---
const SALT_LENGTH = 16;           // 128-bit random salt for PBKDF2 (as recommended in the handout)
const IV_LENGTH = 12;             // 96-bit IV, the recommended size for AES-GCM
// Every password is encrypted inside a fixed-size block so ciphertext length reveals nothing.
// Layout: [2-byte big-endian length][password bytes][zero fill].
// A character can take up to 4 UTF-8 bytes, so the data area is MAX_PASSWORD_LENGTH * 4 bytes.
const PADDED_LENGTH = 2 + MAX_PASSWORD_LENGTH * 4;
// Labels used to derive two independent sub-keys from the PBKDF2 master key (HMAC used as a PRF)
const HMAC_KEY_LABEL = "keychain/v1/domain-hmac-key";
const AES_KEY_LABEL = "keychain/v1/aes-gcm-key";
// Known value encrypted at init time so load() can detect a wrong master password
const CANARY_PLAINTEXT = "keychain/v1/password-check";
const CANARY_AAD = "canary";

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor({ salt, canary, kvs, hmacKey, aesKey }) {
    if (typeof salt !== "string" || canary === undefined || !hmacKey || !aesKey) {
      throw "Keychain constructor: missing salt, canary or keys";
    }

    /* ===================== SHARED CONTRACT (all 3 students) =====================
     * this.data    -> PUBLIC state. dump() serializes exactly this object with
     *                 JSON.stringify(this.data), so everything here must be JSON-safe
     *                 and must not leak anything secret.
     *   data.salt   : Base64 string, 16 random bytes (PBKDF2 salt, stored in the clear)
     *   data.canary : { iv: Base64, ct: Base64 }  AES-GCM encryption of a known value,
     *                 used ONLY by load() to detect a wrong master password
     *   data.kvs    : plain object { Base64(HMAC(hmacKey, domain)) : <record> }
     *                 (<record> format is defined by set(); it must carry its own IV)
     *
     * this.secrets -> PRIVATE state. Never serialized, never logged.
     *   secrets.hmacKey : CryptoKey (HMAC-SHA-256, usages ["sign","verify"])
     *                     -> used to turn a domain name into its kvs key
     *   secrets.aesKey  : CryptoKey (AES-GCM 256, usages ["encrypt","decrypt"])
     *                     -> used to encrypt/decrypt the padded passwords
     * ============================================================================ */
    this.data = {
      salt: salt,
      canary: canary,
      kvs: kvs === undefined ? {} : kvs
    };
    this.secrets = {
      hmacKey: hmacKey,
      aesKey: aesKey
    };
  };

  /* ------------------------------------------------------------------------
   * Helper functions (Student 1). Students 2 and 3 call these; do not
   * re-implement them elsewhere in the file.
   * ---------------------------------------------------------------------- */

  /**
    * Derives the two working keys from the master password. This is the ONLY
    * place PBKDF2 is called, and it is called once per invocation.
    *
    *   PBKDF2(password, salt) -> master key k (HMAC key, never exported)
    *   hmacKey = import( HMAC(k, HMAC_KEY_LABEL) )   // for hashing domain names
    *   aesKey  = import( HMAC(k, AES_KEY_LABEL) )    // for AES-GCM
    *
    * Arguments:
    *   password: string
    *   salt:     buffer (raw bytes, NOT Base64)
    * Return Type: Promise<{ hmacKey: CryptoKey, aesKey: CryptoKey }>
    */
  static async deriveKeys(password, salt) {
    const passwordKey = await subtle.importKey(
      "raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);

    // The single (slow) PBKDF2 call. Output is a non-extractable HMAC key.
    const masterKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      passwordKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]);

    // HMAC as a PRF: two different inputs give two independent pseudorandom sub-keys
    const hmacKeyBytes = await subtle.sign("HMAC", masterKey, stringToBuffer(HMAC_KEY_LABEL));
    const aesKeyBytes = await subtle.sign("HMAC", masterKey, stringToBuffer(AES_KEY_LABEL));

    const hmacKey = await subtle.importKey(
      "raw", hmacKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    const aesKey = await subtle.importKey(
      "raw", aesKeyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);

    return { hmacKey, aesKey };
  }

  /**
    * Pads a password to a fixed-size block (length hiding, Short-answer Q1).
    * Throws if the password is longer than MAX_PASSWORD_LENGTH characters.
    *
    * Arguments:
    *   value: string
    * Return Type: Uint8Array (always exactly PADDED_LENGTH bytes)
    */
  static padPassword(value) {
    if (typeof value !== "string") {
      throw "Password must be a string";
    }
    if (value.length > MAX_PASSWORD_LENGTH) {
      throw "Password exceeds the maximum length of " + MAX_PASSWORD_LENGTH + " characters";
    }
    const bytes = stringToBuffer(value);
    if (bytes.length > PADDED_LENGTH - 2) {
      throw "Password is too large to pad";   // defensive: cannot happen for <= 64 chars
    }
    const padded = new Uint8Array(PADDED_LENGTH);   // zero-filled
    padded[0] = (bytes.length >> 8) & 0xff;
    padded[1] = bytes.length & 0xff;
    padded.set(bytes, 2);
    return padded;
  }

  /**
    * Inverse of padPassword. Call it on the output of AES-GCM decryption.
    *
    * Arguments:
    *   padded: buffer (exactly PADDED_LENGTH bytes)
    * Return Type: string
    */
  static unpadPassword(padded) {
    const buf = new Uint8Array(padded);
    if (buf.length !== PADDED_LENGTH) {
      throw "Corrupted record: unexpected padded length";
    }
    const len = (buf[0] << 8) | buf[1];
    if (len > PADDED_LENGTH - 2) {
      throw "Corrupted record: invalid length prefix";
    }
    return bufferToString(buf.slice(2, 2 + len));
  }

  /**
    * Encrypts a known value under aesKey. Stored in data.canary by init so that
    * load() can tell whether the supplied master password is correct.
    *
    * Arguments:
    *   aesKey: CryptoKey
    * Return Type: Promise<{ iv: string, ct: string }>   (both Base64)
    */
  static async createCanary(aesKey) {
    const iv = getRandomBytes(IV_LENGTH);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(CANARY_AAD) },
      aesKey,
      stringToBuffer(CANARY_PLAINTEXT));
    return { iv: encodeBuffer(iv), ct: encodeBuffer(ct) };
  }

  /**
    * Checks the canary. Throws if the master password is wrong (the derived
    * AES key differs, so GCM authentication fails) or if the canary was tampered with.
    * Student 3 calls this from load().
    *
    * Arguments:
    *   aesKey: CryptoKey
    *   canary: { iv: string, ct: string }   (as read from the serialized data)
    * Return Type: Promise<void>
    */
  static async verifyCanary(aesKey, canary) {
    let plaintext;
    try {
      const ptBuf = await subtle.decrypt(
        { name: "AES-GCM", iv: decodeBuffer(canary.iv), additionalData: stringToBuffer(CANARY_AAD) },
        aesKey,
        decodeBuffer(canary.ct));
      plaintext = bufferToString(ptBuf);
    } catch (e) {
      throw "Invalid master password or corrupted keychain";
    }
    if (plaintext !== CANARY_PLAINTEXT) {
      throw "Invalid master password or corrupted keychain";
    }
  }

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    // Fresh random 128-bit salt, stored in the clear in data.salt
    const salt = getRandomBytes(SALT_LENGTH);

    // One PBKDF2 call, then HMAC-derived sub-keys
    const { hmacKey, aesKey } = await Keychain.deriveKeys(password, salt);

    // Known-value ciphertext so load() can verify the master password later
    const canary = await Keychain.createCanary(aesKey);

    return new Keychain({
      salt: encodeBuffer(salt),
      canary: canary,
      kvs: {},
      hmacKey: hmacKey,
      aesKey: aesKey
    });
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    throw "Not Implemented!";
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    throw "Not Implemented!";
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if (typeof name !== "string") {
      throw "Domain name must be a string";
    }

    // The deterministic HMAC tag is the lookup key, keeping get() O(1)
    // without exposing the domain name in the serialized KVS.
    const tagBytes = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    const tag = encodeBuffer(tagBytes);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return null;
    }

    const record = this.data.kvs[tag];
    try {
      const plaintext = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: decodeBuffer(record.iv),
          // Binding the ciphertext to its HMAC tag detects swapped records,
          // independently of the optional SHA-256 dump checksum.
          additionalData: tagBytes
        },
        this.secrets.aesKey,
        decodeBuffer(record.ct)
      );
      return Keychain.unpadPassword(plaintext);
    } catch (e) {
      throw "Corrupted or swapped password record";
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if (typeof name !== "string") {
      throw "Domain name must be a string";
    }
    if (typeof value !== "string") {
      throw "Password must be a string";
    }

    const tagBytes = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    const tag = encodeBuffer(tagBytes);
    const iv = getRandomBytes(IV_LENGTH);
    const ciphertext = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: tagBytes },
      this.secrets.aesKey,
      Keychain.padPassword(value)
    );

    // A deterministic tag replaces the existing value on update; every write
    // still uses a new IV so encrypting the same value twice yields new ciphertext.
    this.data.kvs[tag] = { iv: encodeBuffer(iv), ct: encodeBuffer(ciphertext) };
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if (typeof name !== "string") {
      throw "Domain name must be a string";
    }

    const tagBytes = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    const tag = encodeBuffer(tagBytes);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return false;
    }
    delete this.data.kvs[tag];
    return true;
  };
};

module.exports = { Keychain }
