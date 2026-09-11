- **PIV slot key self-test.** `keyroostctl piv test --slot <slot>` (and a
  Test button in the GUI slot pane) proves a slot's private key works end to
  end: keyroost builds a fixed challenge from the slot certificate's public
  key, the card runs every operation the key type supports (decrypt for RSA,
  key agreement for P-256/P-384/X25519, sign for RSA/ECDSA/Ed25519), and the
  host verifies each result against that public key. Read-only on the card;
  needs the PIN unless the slot's PIN policy is "never". The verification
  side lives in a new `keyroost-pivtest` crate, which adds `p384`,
  `ed25519-dalek` and `x25519-dalek` (RustCrypto/dalek) to the tree.
  Contributed by @episource. ([#127])
