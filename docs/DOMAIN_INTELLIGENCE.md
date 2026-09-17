# Domain intelligence

Registration lookup is RDAP-first. The service discovers HTTPS RDAP services
from IANA's DNS bootstrap registry, caches the validated TLD map, and queries
only the registrable domain. WHOIS is a best-effort fallback controlled by
`WHOIS_FALLBACK_ENABLED`.

Managed hosting suffixes such as `netlify.app` and `vercel.app` are not queried
as customer registrations. RDAP and WHOIS failures preserve the hostname and
root domain and return unavailable registration data without failing scans.
Timeouts are bounded and raw network exceptions are not shown to users.
