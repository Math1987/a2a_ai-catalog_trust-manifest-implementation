# Public interoperability vectors

`demo/` contains a fixed output of the Rust local demo. All identities are
example domains and all evidence is marked as synthetic. No private key is
included; the generating keys were ephemeral. The artifact is an opaque fixture,
not a valid owner-certified A2A card.

Verify these historical vectors at `demo/report.json.verifyAt`, not today's time:

```sh
.venv/bin/python scripts/verify_demo.py vectors/demo
```

Rust tests also verify the stored baseline and PR entry vectors. The independent
Python checker verifies eight entry/root signatures and the renewal behavior.
These dates and keys must never be used as a live trust configuration.
