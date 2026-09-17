# Milestone 2 completion checklist

- Manual, pasted, and PDF-imported email input use the same deterministic analyzer.
- PDF validation is signature-, MIME-, size-, page-, and text-limited; temporary files are deleted.
- Gmail, Outlook-style, and generic header parsing is conservative and editable.
- Attachment names are metadata only; no attachment file is uploaded, opened, or scanned.
- Scores and evidence are deterministic; Gemini receives summarized findings only and cannot change scores.
- Pending, failed, and completed scans render safely and reports are owner-only.
- Rate limits, body/link/metadata limits, and safe AI fallbacks are enabled.

Milestone 3 attachment scanning is intentionally out of scope.
