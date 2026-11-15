# My Vault

A password manager built on the CS255 Keychain (PBKDF2 + HMAC-tagged domains + AES-GCM + SHA-256 rollback checksum), with a green, green web UI.

    node server.js        # then open http://localhost:3000

No `npm install` needed to run the app (only for the mocha tests).

## UI
- Instagram-style sidebar: icon rail that expands on hover or keyboard focus
- Vault list with search, show/hide, copy (clipboard clears after 20s), delete
- Password generator, strength meter, and a visible idle auto-lock countdown
- Security Lab: raw data, swap attack, rollback attack
