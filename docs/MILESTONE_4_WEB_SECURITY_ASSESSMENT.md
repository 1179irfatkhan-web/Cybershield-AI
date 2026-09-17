# Milestone 4: Authorized Web Security Assessment

CyberShield performs bounded, passive checks only against targets the user owns or is authorized to assess. Requests use SSRF-safe URL validation, bounded responses, and safe redirect handling.

Gemini receives only a sanitized summary; raw HTML, cookies, headers, credentials, and query parameters are excluded.
