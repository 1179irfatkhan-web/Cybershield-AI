# IP intelligence

Reports display only IPv4 and IPv6 addresses already vetted by the hardened
URL validator. No second display-only DNS lookup is performed. Addresses are
normalized, deduplicated, sorted, and separated by IP version. Private,
loopback, link-local, reserved, multicast, unspecified, CGNAT, metadata, and
blocked mapped IPv4 addresses cannot appear in completed reports.

IP data is informational only. CDNs, load balancers, and cloud hosting commonly
produce multiple addresses. Future ASN/provider enrichment must not infer
maliciousness from ASN or geography.
