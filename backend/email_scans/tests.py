from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from services.email_phishing_checker import analyze_email
from services.email_scoring import calculate_email_score
from .models import EmailScan

class EmailServiceTests(TestCase):
    def test_normal_email_is_low_risk(self):
        result = calculate_email_score(analyze_email({"email_body": "Hello team, meeting at 10am.", "body_type": "plain_text", "sender_email": "a@example.com"}))
        self.assertEqual(result["safety_score"], 100)

    def test_mismatch_and_suspicious_links_are_detected(self):
        evidence = analyze_email({"email_body": "URGENT reset your password https://bit.ly/a", "sender_email": "a@example.com", "reply_to": "x@evil.test", "body_type": "plain_text"})
        self.assertTrue(evidence["reply_to_mismatch"])
        self.assertIn("Shortened URL", evidence["link_flags"])
        self.assertLess(calculate_email_score(evidence)["safety_score"], 100)

    def test_html_form_and_risky_attachment(self):
        evidence = analyze_email({"email_body": "<form><input></form>", "body_type": "html", "attachment_metadata": ["invoice.docm"]})
        self.assertTrue(evidence["html_form_detected"])
        self.assertTrue(evidence["attachment_metadata"])

class EmailViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="emailuser", password="password")
        self.client.force_login(self.user)

    def test_create_and_owner_report(self):
        response = self.client.post(reverse("email_scans:create"), {"subject": "Hello", "sender_email": "a@example.com", "email_body": "Hello", "body_type": "plain_text"})
        scan = EmailScan.objects.get(user=self.user)
        self.assertRedirects(response, reverse("email_scans:result", args=[scan.id]))
        self.assertEqual(scan.status, EmailScan.Status.COMPLETED)

    def test_other_user_cannot_open_report(self):
        scan = EmailScan.objects.create(user=self.user, email_body="x")
        other = get_user_model().objects.create_user(username="otheremail", password="password")
        self.client.force_login(other)
        self.assertEqual(self.client.get(reverse("email_scans:result", args=[scan.id])).status_code, 404)
