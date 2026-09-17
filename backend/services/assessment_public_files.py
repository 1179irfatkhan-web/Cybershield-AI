"""Bounded, same-origin public security-file checks."""
from urllib.parse import urljoin, urlsplit
from services.assessment_analyzers import CategoryResult

PUBLIC_PATHS = ("/robots.txt", "/.well-known/security.txt", "/security.txt", "/sitemap.xml")

class PublicFileAnalyzer:
    def __init__(self, fetcher=None):
        self.fetcher = fetcher

    def analyze(self, context):
        checks = list(PUBLIC_PATHS)
        if self.fetcher is None:
            return CategoryResult("public_files", None, status="unavailable", checks_planned=checks, unavailable_checks=["public_files"]).as_dict()
        try:
            origin = f"{urlsplit(context.final_url).scheme}://{urlsplit(context.final_url).netloc}"
            files = {}
            findings = []
            for path in PUBLIC_PATHS:
                target = urljoin(origin + "/", path.lstrip("/"))
                result = self.fetcher(target)
                status = int(result.get("status_code", 0))
                body = (result.get("bounded_body_text", "") or "")[:524288]
                item = {"path": path, "status_code": status, "present": status == 200}
                if path.endswith("security.txt") and status == 200:
                    item["contact_present"] = any(line.lower().startswith("contact:") for line in body.splitlines())
                    item["expires_present"] = any(line.lower().startswith("expires:") for line in body.splitlines())
                files[path] = item
                if status == 200 and path in ("/robots.txt", "/security.txt", "/.well-known/security.txt"):
                    findings.append({"id": "public_file_" + path.strip("/").replace("/", "_"), "title": path + " available", "severity": "info", "status": "passed", "evidence": "Public security file was detected."})
            return CategoryResult("public_files", 100, status="passed", findings=findings, checks_completed=checks, checks_planned=checks).as_dict() | {"files": files}
        except Exception:
            return CategoryResult("public_files", None, status="unavailable", checks_planned=checks, unavailable_checks=["public_files"]).as_dict()
