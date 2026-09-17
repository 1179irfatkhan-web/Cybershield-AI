from types import SimpleNamespace
from unittest.mock import Mock, patch
import uuid
import socket
import ssl

from decouple import UndefinedValueError
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.core.cache import cache
from django.http import HttpResponse
from django.urls import reverse

from config.settings import _parse_bool
from services.ai_explainer import (
    AIExplanationError,
    generate_security_explanation,
)
from services.header_checker import analyze_headers
from services.scoring import calculate_trust_score
from services.ssl_checker import analyze_ssl
from services.redirect_checker import (
    WebsiteRequestError,
    _ConnectionFailure,
    _RequestTimeout,
    fetch_website,
)
from services.ssl_checker import SSLCheckError
from services.ip_intelligence import summarize_vetted_target
from services.url_validator import (
    ResolvedAddress,
    URLValidationError,
    ValidatedTarget,
    validate_url,
    classify_ip,
)

from .models import WebsiteScan


def make_scan_data(**overrides):
    data = {
        "submitted_url": "https://example.com",
        "final_url": "https://example.com",
        "trust_score": 100,
        "risk_level": "low",
        "score_breakdown": [],
        "uses_https": True,
        "https_message": "HTTPS enabled.",
        "http_status_code": 200,
        "redirect_count": 0,
        "redirect_risk": "low",
        "redirect_message": "No redirects.",
        "domain_name": "example.com",
        "domain_type": "Registered Domain",
        "root_domain": "example.com",
        "domain_registrar": "Example Registrar",
        "domain_created_at": None,
        "domain_expires_at": None,
        "domain_age_days": 1000,
        "domain_risk": "low",
        "domain_message": "Domain information available.",
        "is_managed_subdomain": False,
        "hosting_provider": "",
        "phishing_risk": "low",
        "phishing_indicator_count": 0,
        "phishing_indicators": [],
        "phishing_message": "No indicators.",
    }
    data.update(overrides)
    return SimpleNamespace(**data)


class DebugSettingTests(SimpleTestCase):
    def test_parse_bool_accepts_boolean_and_environment_names(self):
        self.assertTrue(_parse_bool("True"))
        self.assertTrue(_parse_bool("development"))
        self.assertFalse(_parse_bool("False"))
        self.assertFalse(_parse_bool("release"))

    def test_parse_bool_rejects_unknown_values(self):
        with self.assertRaisesMessage(Exception, "DEBUG must be a Boolean"):
            _parse_bool("maybe")


class AIExplainerTests(SimpleTestCase):
    @patch("services.ai_explainer.genai.Client")
    @patch("services.ai_explainer.config")
    def test_success_returns_generated_explanation(self, config_mock, client_mock):
        config_mock.side_effect = lambda name: {
            "GEMINI_API_KEY": "test-key",
            "GEMINI_MODEL": "test-model",
        }[name]
        client_mock.return_value.models.generate_content.return_value.text = (
            "Generated explanation"
        )

        result = generate_security_explanation(make_scan_data())

        self.assertEqual(result, "Generated explanation")

    @patch("services.ai_explainer.config", side_effect=UndefinedValueError("missing"))
    def test_missing_configuration_becomes_ai_explanation_error(self, _config):
        with self.assertRaises(AIExplanationError):
            generate_security_explanation(make_scan_data())

    @patch("services.ai_explainer.config")
    def test_missing_model_becomes_ai_explanation_error(self, config_mock):
        config_mock.side_effect = [
            "test-key",
            UndefinedValueError("missing model"),
        ]

        with self.assertRaises(AIExplanationError):
            generate_security_explanation(make_scan_data())

    @patch("services.ai_explainer.config")
    def test_blank_model_becomes_ai_explanation_error(self, config_mock):
        config_mock.side_effect = ["test-key", "  "]

        with self.assertRaises(AIExplanationError):
            generate_security_explanation(make_scan_data())

    @patch("services.ai_explainer.genai.Client", side_effect=RuntimeError("failed"))
    @patch("services.ai_explainer.config")
    def test_client_failure_becomes_ai_explanation_error(
        self, config_mock, _client
    ):
        config_mock.side_effect = lambda name: {
            "GEMINI_API_KEY": "test-key",
            "GEMINI_MODEL": "test-model",
        }[name]

        with self.assertRaises(AIExplanationError):
            generate_security_explanation(make_scan_data())

    @patch("services.ai_explainer.time.sleep")
    @patch("services.ai_explainer.genai.Client")
    @patch("services.ai_explainer.config")
    def test_generation_failure_becomes_ai_explanation_error(
        self, config_mock, client_mock, _sleep
    ):
        config_mock.side_effect = lambda name: {
            "GEMINI_API_KEY": "test-key",
            "GEMINI_MODEL": "test-model",
        }[name]
        client_mock.return_value.models.generate_content.side_effect = RuntimeError(
            "failed"
        )

        with self.assertRaises(AIExplanationError):
            generate_security_explanation(make_scan_data())

    @patch("services.ai_explainer.time.sleep")
    @patch("services.ai_explainer.genai.Client")
    @patch("services.ai_explainer.config")
    def test_empty_response_becomes_ai_explanation_error(
        self, config_mock, client_mock, _sleep
    ):
        config_mock.side_effect = lambda name: {
            "GEMINI_API_KEY": "test-key",
            "GEMINI_MODEL": "test-model",
        }[name]
        client_mock.return_value.models.generate_content.return_value.text = ""

        with self.assertRaises(AIExplanationError):
            generate_security_explanation(make_scan_data())


class ScanResultTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="owner", password="test-password"
        )
        self.other_user = user_model.objects.create_user(
            username="other", password="test-password"
        )
        self.client.force_login(self.user)

    def create_scan(self, **overrides):
        data = {
            "user": self.user,
            "submitted_url": "https://example.com",
            "normalized_url": "https://example.com",
        }
        data.update(overrides)
        return WebsiteScan.objects.create(**data)

    def test_owner_can_open_scan(self):
        scan = self.create_scan(status=WebsiteScan.Status.COMPLETED)

        response = self.client.get(reverse("scans:result", args=[scan.id]))

        self.assertEqual(response.status_code, 200)

    def test_another_users_scan_returns_404(self):
        scan = self.create_scan(
            user=self.other_user,
            status=WebsiteScan.Status.COMPLETED,
        )

        response = self.client.get(reverse("scans:result", args=[scan.id]))

        self.assertEqual(response.status_code, 404)

    def test_missing_scan_returns_404(self):
        response = self.client.get(
            reverse("scans:result", args=[uuid.uuid4()])
        )

        self.assertEqual(response.status_code, 404)

    def test_pending_scan_shows_only_pending_state(self):
        scan = self.create_scan(status=WebsiteScan.Status.PENDING)

        response = self.client.get(reverse("scans:result", args=[scan.id]))

        self.assertContains(response, "This scan is pending")
        self.assertNotContains(response, "Overall Trust Score")
        self.assertNotContains(response, "HTTPS Analysis")
        self.assertNotContains(response, "No deductions were applied")

    def test_failed_scan_shows_reason_without_findings(self):
        scan = self.create_scan(
            status=WebsiteScan.Status.FAILED,
            error_message="Website request timed out.",
        )

        response = self.client.get(reverse("scans:result", args=[scan.id]))

        self.assertContains(response, "Scan failed")
        self.assertContains(response, "Website request timed out.")
        self.assertNotContains(response, "Overall Trust Score")
        self.assertNotContains(response, "HTTPS Analysis")
        self.assertNotContains(response, "No deductions were applied")
        self.assertNotContains(response, "AI Security Explanation")

    def test_completed_scan_shows_full_report(self):
        scan = self.create_scan(
            status=WebsiteScan.Status.COMPLETED,
            trust_score=90,
            uses_https=True,
            https_message="HTTPS enabled.",
            ai_security_report="Completed AI explanation.",
        )

        response = self.client.get(reverse("scans:result", args=[scan.id]))

        self.assertContains(response, "Overall Trust Score")
        self.assertContains(response, "90/100")
        self.assertContains(response, "HTTPS Analysis")
        self.assertContains(response, "Completed AI explanation.")


class ScanCreationAIIsolationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="scanner", password="test-password"
        )
        self.client.force_login(self.user)

    @patch(
        "scans.views.generate_security_explanation",
        side_effect=AIExplanationError("unavailable"),
    )
    @patch("scans.views.analyze_ssl", side_effect=SSLCheckError("unavailable"))
    @patch("scans.views.analyze_domain")
    @patch("scans.views.fetch_website")
    @patch("scans.views.validate_url")
    def test_scan_is_completed_and_saved_when_gemini_fails(
        self,
        validate_url_mock,
        fetch_website_mock,
        analyze_domain_mock,
        _analyze_ssl,
        _generate_explanation,
    ):
        validate_url_mock.return_value = ValidatedTarget(
            normalized_url="https://example.com",
            scheme="https",
            hostname="example.com",
            port=443,
            addresses=(),
        )
        fetch_website_mock.return_value = {
            "status_code": 200,
            "final_url": "https://example.com",
            "redirect_count": 0,
            "headers": {},
            "redirect_chain": [],
            "redirect_cross_host_count": 0,
            "redirect_has_scheme_downgrade": False,
            "redirect_loop_detected": False,
        }
        analyze_domain_mock.return_value = {
            "domain_name": "example.com",
            "registrar": "Example Registrar",
            "creation_date": None,
            "expiration_date": None,
            "age_days": 1000,
            "risk": "low",
            "message": "Domain information available.",
            "hosting_provider": "",
            "domain_type": "Registered Domain",
            "root_domain": "example.com",
            "is_managed_subdomain": False,
        }

        response = self.client.post(
            reverse("scans:create"),
            {"submitted_url": "https://example.com"},
        )

        scan = WebsiteScan.objects.get(user=self.user)
        self.assertRedirects(response, reverse("scans:result", args=[scan.id]))
        self.assertEqual(scan.status, WebsiteScan.Status.COMPLETED)
        self.assertIn("could not generate", scan.ai_security_report)


class ScanLimitTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="limited", password="test-password")
        self.client.force_login(self.user)

    @override_settings(SCAN_RATE_LIMIT_COUNT=1, SCAN_RATE_LIMIT_WINDOW_SECONDS=60)
    @patch("scans.views._run_scan", return_value=HttpResponse("ok"))
    def test_rate_limit_is_backend_enforced(self, run_scan):
        cache.clear()
        self.client.post(reverse("scans:create"), {"submitted_url": "https://example.com"})
        response = self.client.post(reverse("scans:create"), {"submitted_url": "https://example.com"})
        self.assertContains(response, "Scan limit reached")
        self.assertEqual(run_scan.call_count, 1)

    @override_settings(SCAN_DAILY_QUOTA=1)
    @patch("scans.views._run_scan", return_value=HttpResponse("ok"))
    def test_daily_quota_is_enforced(self, run_scan):
        cache.clear()
        self.client.post(reverse("scans:create"), {"submitted_url": "https://example.com"})
        response = self.client.post(reverse("scans:create"), {"submitted_url": "https://example.com"})
        self.assertContains(response, "Scan limit reached")

    @patch("scans.views.cache.get", side_effect=RuntimeError("cache unavailable"))
    @patch("scans.views._run_scan", return_value=HttpResponse("ok"))
    def test_cache_failure_fails_open(self, run_scan, _cache_get):
        self.client.post(reverse("scans:create"), {"submitted_url": "https://example.com"})
        run_scan.assert_called_once()


class URLValidationTests(SimpleTestCase):
    def address_results(self, *addresses):
        return [
            (socket_family, 1, 6, "", sockaddr)
            for socket_family, sockaddr in addresses
        ]

    @patch("services.url_validator.socket.getaddrinfo")
    def test_valid_public_target_returns_structured_target(self, resolver):
        resolver.return_value = self.address_results(
            (socket.AF_INET, ("93.184.216.34", 443))
        )

        target = validate_url("https://example.com/path#fragment")

        self.assertEqual(target.normalized_url, "https://example.com/path")
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.vetted_ip_addresses, ("93.184.216.34",))

    @patch("services.url_validator.socket.getaddrinfo")
    def test_mixed_dns_results_reject_if_any_address_is_blocked(self, resolver):
        resolver.return_value = self.address_results(
            (socket.AF_INET, ("93.184.216.34", 443)),
            (socket.AF_INET, ("127.0.0.1", 443)),
        )

        with self.assertRaises(URLValidationError):
            validate_url("https://example.com")

    @patch("services.url_validator.socket.getaddrinfo")
    def test_blocked_address_forms_are_rejected(self, resolver):
        blocked = [
            (socket.AF_INET, "127.0.0.1"),
            (socket.AF_INET, "10.0.0.1"),
            (socket.AF_INET, "169.254.169.254"),
            (socket.AF_INET, "100.64.0.1"),
            (socket.AF_INET6, "::1"),
            (socket.AF_INET6, "fe80::1"),
            (socket.AF_INET6, "::ffff:127.0.0.1"),
        ]

        for family, ip in blocked:
            resolver.return_value = self.address_results(
                (family, (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443))
            )
            with self.subTest(ip=ip), self.assertRaises(URLValidationError):
                validate_url("https://example.com")


class IPIntelligenceTests(SimpleTestCase):
    def target(self, addresses):
        return ValidatedTarget("https://example.com", "https", "example.com", 443, tuple(addresses))

    def test_public_addresses_are_sorted_deduplicated_and_separated(self):
        values = [
            ResolvedAddress("2606:4700:4700::1111", 10, 1, 6, ("2606:4700:4700::1111", 443, 0, 0)),
            ResolvedAddress("93.184.216.34", 2, 1, 6, ("93.184.216.34", 443)),
        ]
        result = summarize_vetted_target(self.target(values))
        self.assertEqual(result["ipv4_addresses"], ["93.184.216.34"])
        self.assertEqual(result["ipv6_addresses"], ["2606:4700:4700::1111"])
        self.assertEqual(result["resolution_status"], "completed")

    def test_non_global_vetted_address_never_returns_in_report(self):
        values = [ResolvedAddress("127.0.0.1", 2, 1, 6, ("127.0.0.1", 443))]
        result = summarize_vetted_target(self.target(values))
        self.assertEqual(result["resolution_status"], "blocked")
        self.assertEqual(result["ipv4_addresses"], [])

    def test_safe_nat64_embeds_public_ipv4(self):
        result = classify_ip("64:ff9b::67a0:6b93")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["address_type"], "nat64")
        self.assertEqual(result["embedded_ipv4"], "103.160.107.147")

    def test_nat64_embedded_private_targets_are_rejected(self):
        for address in ("64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::c0a8:101", "64:ff9b::6440:1"):
            with self.subTest(address=address), self.assertRaises(URLValidationError):
                classify_ip(address)

    def test_other_reserved_ipv6_remains_rejected(self):
        with self.assertRaises(URLValidationError):
            classify_ip("2001:db8::1")

    @patch("services.url_validator.socket.getaddrinfo")
    def test_credentials_scheme_and_unusual_port_are_rejected(self, resolver):
        cases = (
            "https://user:pass@example.com",
            "ftp://example.com",
            "https://example.com:8443",
        )
        for url in cases:
            with self.subTest(url=url), self.assertRaises(URLValidationError):
                validate_url(url)
        resolver.assert_not_called()


class RedirectSecurityTests(SimpleTestCase):
    def target(self, url, scheme="https", hostname="example.com"):
        return ValidatedTarget(url, scheme, hostname, 443 if scheme == "https" else 80, ())

    @patch("services.redirect_checker.validate_url")
    @patch("services.redirect_checker._request_once")
    def test_relative_redirect_is_resolved_and_cross_host_recorded(self, request, validator):
        start = self.target("https://example.com/start")
        destination = self.target("https://other.example/final", hostname="other.example")
        request.side_effect = [
            SimpleNamespace(status_code=302, headers={"location": "/next"}),
            SimpleNamespace(status_code=200, headers={"content-type": "text/html"}),
        ]
        validator.return_value = destination

        result = fetch_website(start)

        self.assertEqual(result["redirect_count"], 1)
        self.assertEqual(result["redirect_cross_host_count"], 1)
        self.assertEqual(result["redirect_chain"][0]["destination_url"], "https://other.example/final")
        validator.assert_called_once_with("https://example.com/next")

    @patch("services.redirect_checker.validate_url")
    @patch("services.redirect_checker._request_once")
    def test_downgrade_is_recorded(self, request, validator):
        start = self.target("https://example.com", hostname="example.com")
        destination = self.target("http://example.com/final", scheme="http", hostname="example.com")
        request.side_effect = [
            SimpleNamespace(status_code=301, headers={"location": "http://example.com/final"}),
            SimpleNamespace(status_code=200, headers={}),
        ]
        validator.return_value = destination

        result = fetch_website(start)

        self.assertTrue(result["redirect_has_scheme_downgrade"])

    @patch("services.redirect_checker.validate_url")
    @patch("services.redirect_checker._request_once")
    def test_redirect_loop_and_excessive_redirects_fail(self, request, validator):
        start = self.target("https://example.com", hostname="example.com")
        validator.return_value = start
        request.return_value = SimpleNamespace(
            status_code=302,
            headers={"location": "https://example.com"},
        )

        with self.assertRaises(WebsiteRequestError) as context:
            fetch_website(start)
        self.assertTrue(context.exception.loop_detected)


class SSLAndHeaderTests(SimpleTestCase):
    def target(self, url, scheme="https", hostname="example.com"):
        return ValidatedTarget(url, scheme, hostname, 443 if scheme == "https" else 80, ())

    def ssl_socket(self, cert, version="TLSv1.3"):
        secure = Mock()
        secure.__enter__ = Mock(return_value=secure)
        secure.__exit__ = Mock(return_value=False)
        secure.getpeercert.return_value = cert
        secure.version.return_value = version
        secure.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        context = Mock()
        context.wrap_socket.return_value = secure
        return context

    @patch("services.ssl_checker.socket.create_connection")
    @patch("services.ssl_checker.ssl.create_default_context")
    def test_valid_certificate_is_classified(self, context_factory, connect):
        cert = {
            "notBefore": "Jan 01 00:00:00 2020 GMT",
            "notAfter": "Jan 01 00:00:00 2099 GMT",
            "issuer": (("organizationName", "Test CA"),),
            "subject": (("commonName", "example.com"),),
            "subjectAltName": (("DNS", "example.com"),),
        }
        context_factory.return_value = self.ssl_socket(cert)
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        connect.return_value = sock

        result = analyze_ssl("https://example.com")

        self.assertTrue(result["certificate_present"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["tls_version"], "TLSv1.3")
        self.assertIn("Test CA", result["issuer"])

    @patch("services.ssl_checker.socket.create_connection", side_effect=socket.timeout)
    def test_timeout_is_classified(self, _connect):
        with self.assertRaisesMessage(SSLCheckError, "timed out"):
            analyze_ssl("https://example.com")

    @patch("services.ssl_checker.socket.create_connection")
    @patch("services.ssl_checker.ssl.create_default_context")
    def test_expired_certificate_is_classified(self, context_factory, connect):
        cert = {
            "notBefore": "Jan 01 00:00:00 2020 GMT",
            "notAfter": "Jan 01 00:00:00 2021 GMT",
            "issuer": (), "subject": (), "subjectAltName": (),
        }
        context_factory.return_value = self.ssl_socket(cert)
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        connect.return_value = sock

        result = analyze_ssl("https://example.com")

        self.assertTrue(result["expired"])
        self.assertFalse(result["valid"])

    @patch("services.ssl_checker.socket.create_connection", side_effect=ssl.SSLError("handshake"))
    def test_handshake_failure_is_classified(self, _connect):
        with self.assertRaisesMessage(SSLCheckError, "handshake failed"):
            analyze_ssl("https://example.com")

    def test_missing_and_perfect_headers_are_scored(self):
        missing = analyze_headers({"strict-transport-security": "max-age=31536000"})
        perfect = analyze_headers({name: "enabled" for name in (
            "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
            "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
            "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy",
        )})
        self.assertIn("content-security-policy", missing["missing"])
        self.assertEqual(perfect["score"], 100)
        self.assertEqual(perfect["risk"], "low")

    def test_score_includes_available_ssl_and_header_deductions(self):
        scan = SimpleNamespace(
            uses_https=True, ssl_valid=True, ssl_expired=True,
            ssl_days_remaining=0, headers_score=30,
            headers_missing=["content-security-policy", "x-frame-options"],
            redirect_risk="low", domain_risk="low", phishing_score_penalty=0,
        )
        result = calculate_trust_score(scan)
        self.assertEqual(result["score"], 67)
        self.assertIn("Expired TLS certificate (-20)", result["deductions"])

    def test_unavailable_important_checks_prevent_perfect_score(self):
        scan = SimpleNamespace(
            uses_https=True, ssl_valid=None, ssl_expired=None,
            ssl_days_remaining=None, headers_score=None, headers_missing=[],
            redirect_risk="low", domain_risk="low", phishing_score_penalty=0,
        )
        self.assertLess(calculate_trust_score(scan)["score"], 100)

    @patch("services.redirect_checker.validate_url", side_effect=URLValidationError("blocked"))
    @patch("services.redirect_checker._request_once")
    def test_blocked_redirect_fails_without_following_it(self, request, _validator):
        start = self.target("https://example.com", hostname="example.com")
        request.return_value = SimpleNamespace(
            status_code=302,
            headers={"location": "http://127.0.0.1/admin"},
        )

        with self.assertRaisesMessage(
            WebsiteRequestError,
            "unsafe or invalid destination",
        ):
            fetch_website(start)
        request.assert_called_once()

    @patch("services.redirect_checker._request_once")
    def test_missing_location_fails_safely(self, request):
        start = self.target("https://example.com", hostname="example.com")
        request.return_value = SimpleNamespace(status_code=302, headers={})

        with self.assertRaisesMessage(WebsiteRequestError, "malformed redirect"):
            fetch_website(start)

    @patch("services.redirect_checker._request_once", side_effect=_RequestTimeout)
    def test_timeout_is_returned_as_safe_user_error(self, _request):
        with self.assertRaisesMessage(WebsiteRequestError, "too long"):
            fetch_website(self.target("https://example.com"))

    @patch("services.redirect_checker._request_once", side_effect=_ConnectionFailure)
    def test_connection_failure_is_returned_as_safe_user_error(self, _request):
        with self.assertRaisesMessage(WebsiteRequestError, "could not connect"):
            fetch_website(self.target("https://example.com"))

    @patch("services.redirect_checker.validate_url")
    @patch("services.redirect_checker._request_once")
    def test_excessive_redirects_are_rejected(self, request, validator):
        start = self.target("https://example.com/0", hostname="example.com")
        destinations = [
            self.target(
                f"https://example.com/{index}",
                hostname="example.com",
            )
            for index in range(1, 7)
        ]
        validator.side_effect = destinations
        request.return_value = SimpleNamespace(
            status_code=302,
            headers={"location": "/next"},
        )

        with self.assertRaisesMessage(WebsiteRequestError, "too many redirects"):
            fetch_website(start)
