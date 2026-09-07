- **PIV management-key authentication no longer assumes 3DES on cards that
  lack GET METADATA.** That Yubico extension is the only place a card reports
  its 9B key's algorithm, and applets without it (the Cryptnox OpenFIPS201
  variant, which ships with an AES key) were authenticated as 3DES and
  failed. When the extension is absent, keyroost now probes each algorithm
  with a bare GENERAL AUTHENTICATE witness request (no key material leaves
  the host), keeps the ones the card accepts, and narrows by the length of
  the key in hand; a 24-byte key that fits both 3DES and AES-192 still
  resolves to 3DES, so older YubiKeys behave as before. Applies to the CLI
  and the GUI alike, and `--debug` traces each probe's verdict. Contributed
  by @episource. ([#124])
