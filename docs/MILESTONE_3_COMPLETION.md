# Milestone 3 acceptance checklist

- Authenticated owner-only attachment upload, history, and reports.
- Supported document, archive, executable, script, APK, and common image formats are validated by extension, MIME, and magic bytes.
- Uploads are bounded at 200 MB and processed in temporary storage with cleanup in `finally`.
- Hashes are calculated in chunks; files are never executed, rendered, installed, or sent to third parties.
- Image analysis is structural only and never exposes previews or exact location metadata to AI.
- Deterministic score, confidence, completeness, and warnings remain separate.
- Static analysis cannot guarantee that a clean file is harmless.

YARA, antivirus engines, sandboxing, reputation lookups, and threat-intelligence integrations remain intentionally out of scope.
