#!/usr/bin/env python3
"""Hash only named public verification code/evidence, never keys or environments."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
names = (
    "independent/verify_catalog.py", "independent/check_vectors.py",
    "independent/test_helpers.py", "independent/requirements.txt",
    "independent/README.md", "independent/record_artifacts.py",
    "independent/helper-test-results.json", "independent/vector-results.json",
    "proof-docs/DARREL_EVIDENCE.md", "proof-docs/DARREL_COMMENT_DRAFT.md",
)
report = {"created_at": datetime.now(timezone.utc).isoformat(),
          "spec_revision": "2973e3ae00e43d27d24fa7c9a3b1d1ed5d811aad", "files": {}}
for name in names:
    raw = (root / name).read_bytes()
    report["files"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
output = root / "independent/verification-artifacts.json"
output.write_text(json.dumps(report, indent=2) + "\n")
print(str(output))
