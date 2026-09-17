# Operations

Scans are saved as pending before outbound work and become completed only after
deterministic checks finish. Unexpected errors create a failed record with a
generic user message and structured logs containing scan/user IDs, stage, and
error category. The MVP uses cache-based per-user limits: three submissions per
60 seconds and 25 per day by default. Cache errors fail open and are logged.

Timeouts are configured through `SCAN_CONNECT_TIMEOUT`, `SCAN_READ_TIMEOUT`,
and `SCAN_TOTAL_TIMEOUT`. The scanner uses bounded redirects and response
sampling. WHOIS and Gemini remain optional stages.
