"""Passive, non-invasive technology awareness."""
import re
from services.assessment_analyzers import CategoryResult

class TechnologyAnalyzer:
    def analyze(self, context):
        try:
            headers = {str(k).lower(): str(v) for k, v in context.headers.items()}
            text = context.bounded_body or ""
            technologies = []
            sources = (("server", headers.get("server", "")), ("x-powered-by", headers.get("x-powered-by", "")), ("x-generator", headers.get("x-generator", "")), ("x-cms", headers.get("x-cms", "")))
            for source, value in sources:
                if value:
                    technologies.append({"name": value.split("/")[0].strip(), "version": (value.split("/", 1)[1] if "/" in value else ""), "source": source})
            for name, pattern in (("WordPress", r"wp-includes|wp-content"), ("Django", r"csrfmiddlewaretoken|django"), ("React", r"react(?:\.min)?\.js"), ("Bootstrap", r"bootstrap(?:\.min)?\.(?:css|js)"), ("Next.js", r"/_next/")):
                if re.search(pattern, text, re.I):
                    technologies.append({"name": name, "version": "", "source": "html"})
            names = {item["name"] for item in technologies}
            return CategoryResult("technology", 100, status="passed", checks_completed=["headers", "html", "cookies"], checks_planned=["headers", "html", "cookies"]).as_dict() | {"technologies": list({(item["name"], item["source"]): item for item in technologies}.values())}
        except Exception:
            return CategoryResult("technology", None, status="unavailable", checks_planned=["headers", "html", "cookies"], unavailable_checks=["technology"]).as_dict()
