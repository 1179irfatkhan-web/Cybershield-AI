# CyberShield AI scoring methodology

Version 1.0 assigns a maximum contribution to each deterministic check:

| Check | Maximum |
| --- | ---: |
| HTTPS/transport | 15 |
| TLS certificate | 20 |
| Security headers | 25 |
| Redirect safety | 10 |
| Domain intelligence | 10 |
| Phishing URL analysis | 20 |

The trust score is the sum of each check's contribution. Passed checks receive
the full contribution, warnings receive half, and failed or unavailable checks
receive zero. Missing HSTS, CSP, X-Frame-Options, and X-Content-Type-Options
are recorded as explicit deductions. Evidence is not deducted twice for HTTPS
and TLS.

Confidence and completeness are the percentage of the six deterministic checks
that reached a terminal state (passed, warning, or failed). Unavailable checks
reduce both values; they never count as passed. Risk thresholds are low at
90+ with at least 90% confidence, medium at 70+, high at 40+, and critical
below 40. Scores with under 50% confidence are labelled unknown.

Gemini is explanatory only and cannot change deterministic scores. A high score
is evidence of observed controls, not a guarantee that a site is safe.
