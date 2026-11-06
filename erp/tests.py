from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch

from erp.models import EmailOTP

User = get_user_model()


class OTPAuthAPITests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.signup_url = "/api/signup/"
        self.verify_otp_url = "/api/verify-otp/"
        self.resend_otp_url = "/api/resend-otp/"
        self.login_url = "/api/login/"
        self.forgot_pw_url = "/api/forgot-password/"
        self.forgot_pw_verify_url = "/api/forgot-password/verify-otp/"
        self.reset_pw_url = "/api/forgot-password/reset-password/"

        self.signup_payload = {
            "first_name": "Test",
            "last_name": "User",
            "email": "tester@example.com",
            "password": "StrongPassword@123",
            "confirm_password": "StrongPassword@123",
            "role": "TECH",
        }

    @patch("erp.views.send_otp_email", return_value=(True, None))
    def test_signup_creates_inactive_user_and_generates_otp(self, mock_send_email):
        response = self.client.post(self.signup_url, self.signup_payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["success"])

        # User must be inactive until OTP is verified
        user = User.objects.get(email="tester@example.com")
        self.assertFalse(user.is_active)
        self.assertFalse(user.is_email_verified)

        # EmailOTP record must exist
        otp_record = EmailOTP.objects.filter(email="tester@example.com", purpose="SIGNUP").first()
        self.assertIsNotNone(otp_record)
        self.assertEqual(len(otp_record.otp), 6)
        self.assertFalse(otp_record.is_verified)

        # send_otp_email must have been called
        mock_send_email.assert_called_once_with("tester@example.com", otp_record.otp, purpose="SIGNUP")

    @patch("erp.views.send_otp_email", return_value=(True, None))
    def test_unverified_user_cannot_login(self, mock_send_email):
        # Sign up
        self.client.post(self.signup_url, self.signup_payload, format="json")

        # Attempt to login
        login_response = self.client.post(
            self.login_url,
            {"email": "tester@example.com", "password": "StrongPassword@123"},
            format="json",
        )

        self.assertEqual(login_response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(login_response.data["success"])
        self.assertIn("not verified", login_response.data["message"])

    @patch("erp.views.send_otp_email", return_value=(True, None))
    def test_verify_otp_invalid_code(self, mock_send_email):
        # Sign up
        self.client.post(self.signup_url, self.signup_payload, format="json")

        # Attempt wrong OTP
        verify_response = self.client.post(
            self.verify_otp_url,
            {"email": "tester@example.com", "otp": "000000"},
            format="json",
        )

        self.assertEqual(verify_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(verify_response.data["success"])

    @patch("erp.views.send_otp_email", return_value=(True, None))
    def test_verify_otp_success(self, mock_send_email):
        # Sign up
        self.client.post(self.signup_url, self.signup_payload, format="json")
        otp_record = EmailOTP.objects.filter(email="tester@example.com", purpose="SIGNUP").first()

        # Verify correct OTP
        verify_response = self.client.post(
            self.verify_otp_url,
            {"email": "tester@example.com", "otp": otp_record.otp},
            format="json",
        )

        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        self.assertTrue(verify_response.data["success"])
        self.assertIn("access", verify_response.data["data"])
        self.assertIn("refresh", verify_response.data["data"])

        # Check user is now active & verified
        user = User.objects.get(email="tester@example.com")
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_email_verified)

        # Check OTP record is marked verified
        otp_record.refresh_from_db()
        self.assertTrue(otp_record.is_verified)

        # Now login should succeed
        login_response = self.client.post(
            self.login_url,
            {"email": "tester@example.com", "password": "StrongPassword@123"},
            format="json",
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertTrue(login_response.data["success"])

    @patch("erp.utils.send_mail", return_value=1)
    @patch("erp.views.send_otp_email", return_value=(True, None))
    def test_resend_otp(self, mock_send_email, mock_send_mail):
        # Sign up
        self.client.post(self.signup_url, self.signup_payload, format="json")

        # Request resend
        resend_response = self.client.post(
            self.resend_otp_url,
            {"email": "tester@example.com"},
            format="json",
        )

        self.assertEqual(resend_response.status_code, status.HTTP_200_OK)
        self.assertTrue(resend_response.data["success"])

        # Two OTP records should now exist for SIGNUP
        otps = EmailOTP.objects.filter(email="tester@example.com", purpose="SIGNUP")
        self.assertEqual(otps.count(), 2)

    # --- Forgot Password Tests ---

    @patch("erp.views.send_otp_email", return_value=(True, None))
    def test_forgot_password_request_nonexistent_email(self, mock_send_email):
        res = self.client.post(self.forgot_pw_url, {"email": "notfound@example.com"}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(res.data["success"])

    @patch("erp.views.send_otp_email", return_value=(True, None))
    def test_forgot_password_flow_complete(self, mock_send_email):
        # 1. Create active user
        User.objects.create_user(
            email="existing@drdesigntech.com",
            password="OldPassword@123",
            first_name="Existing",
            last_name="User",
            role="TECH",
            is_active=True,
            is_email_verified=True,
        )

        # 2. Request forgot password OTP
        res_req = self.client.post(
            self.forgot_pw_url,
            {"email": "existing@drdesigntech.com"},
            format="json",
        )
        self.assertEqual(res_req.status_code, status.HTTP_200_OK)
        self.assertTrue(res_req.data["success"])

        otp_record = EmailOTP.objects.filter(
            email="existing@drdesigntech.com",
            purpose="FORGOT_PASSWORD"
        ).first()
        self.assertIsNotNone(otp_record)
        mock_send_email.assert_called_with("existing@drdesigntech.com", otp_record.otp, purpose="FORGOT_PASSWORD")

        # 3. Verify OTP
        res_verify = self.client.post(
            self.forgot_pw_verify_url,
            {"email": "existing@drdesigntech.com", "otp": otp_record.otp},
            format="json",
        )
        self.assertEqual(res_verify.status_code, status.HTTP_200_OK)
        self.assertTrue(res_verify.data["success"])
        reset_token = res_verify.data["data"]["reset_token"]
        self.assertTrue(bool(reset_token))

        # 4. Set new password
        res_reset = self.client.post(
            self.reset_pw_url,
            {
                "email": "existing@drdesigntech.com",
                "reset_token": reset_token,
                "new_password": "BrandNewPassword@2026#",
                "confirm_password": "BrandNewPassword@2026#",
            },
            format="json",
        )
        self.assertEqual(res_reset.status_code, status.HTTP_200_OK)
        self.assertTrue(res_reset.data["success"])

        # 5. Check login with old password fails
        login_old = self.client.post(
            self.login_url,
            {"email": "existing@drdesigntech.com", "password": "OldPassword@123"},
            format="json",
        )
        self.assertEqual(login_old.status_code, status.HTTP_401_UNAUTHORIZED)

        # 6. Check login with new password succeeds
        login_new = self.client.post(
            self.login_url,
            {"email": "existing@drdesigntech.com", "password": "BrandNewPassword@2026#"},
            format="json",
        )
        self.assertEqual(login_new.status_code, status.HTTP_200_OK)
        self.assertTrue(login_new.data["success"])


from erp.models import Lead


class LeadAPITests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.leads_url = "/api/leads/"

        # Create a lead gen user
        self.user = User.objects.create_user(
            email="leadagent@drdesigntech.com",
            password="AgentPassword@123",
            first_name="Agent",
            last_name="One",
            role="LEAD_GEN",
            is_active=True,
            is_email_verified=True,
        )

        self.valid_lead_payload = {
            "client_full_name": "Aarav Sharma",
            "client_email": "aarav.sharma@innovatetech.in",
            "client_company_name": "Innovate Tech Pvt Ltd",
            "client_website_address": "https://innovatetech.in",
            "client_is": "Domestic",
            "country_name": "India",
            "client_full_address": "Tower B, Sector 62, Noida, Uttar Pradesh 201309",
            "client_contact_number": "+91 9876543210",
            "lead_type": "Hot",
            "project_category": "Website Design & Development",
            "requirement_description": "We need a complete responsive corporate website redesign with CMS integration and modern UI.",
            "status": "Open",
            "next_follow_up": "Yes",
            "lead_generated_from": "Calling",
        }

    def test_unauthenticated_user_cannot_create_lead(self):
        response = self.client.post(self.leads_url, self.valid_lead_payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authenticated_user_can_create_lead(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.leads_url, self.valid_lead_payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["success"])
        self.assertEqual(response.data["data"]["client_full_name"], "Aarav Sharma")
        self.assertTrue(response.data["data"]["lead_id"].startswith("DR-LEAD-"))
        self.assertEqual(response.data["data"]["created_by_email"], "leadagent@drdesigntech.com")

        # Verify in DB
        lead = Lead.objects.get(client_email="aarav.sharma@innovatetech.in")
        self.assertEqual(lead.client_company_name, "Innovate Tech Pvt Ltd")
        self.assertEqual(lead.created_by, self.user)

    def test_short_requirement_description_fails(self):
        self.client.force_authenticate(user=self.user)
        invalid_payload = self.valid_lead_payload.copy()
        invalid_payload["requirement_description"] = "Too short description"

        response = self.client.post(self.leads_url, invalid_payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["success"])
        self.assertIn("requirement_description", response.data["errors"])

    def test_get_leads_authenticated(self):
        self.client.force_authenticate(user=self.user)
        self.client.post(self.leads_url, self.valid_lead_payload, format="json")

        response = self.client.get(self.leads_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        self.assertGreaterEqual(response.data["count"], 1)


    def test_update_lead_success(self):
        self.client.force_authenticate(user=self.user)
        create_res = self.client.post(self.leads_url, self.valid_lead_payload, format="json")
        lead_id = create_res.data["data"]["id"]

        update_payload = {
            "status": "In Progress",
            "next_follow_up": "No",
        }
        update_res = self.client.patch(f"/api/leads/{lead_id}/", update_payload, format="json")
        self.assertEqual(update_res.status_code, status.HTTP_200_OK)
        self.assertTrue(update_res.data["success"])
        self.assertEqual(update_res.data["data"]["status"], "In Progress")
        self.assertEqual(update_res.data["data"]["next_follow_up"], "No")

    def test_delete_lead_success(self):
        self.client.force_authenticate(user=self.user)
        create_res = self.client.post(self.leads_url, self.valid_lead_payload, format="json")
        lead_id = create_res.data["data"]["id"]

        delete_res = self.client.delete(f"/api/leads/{lead_id}/")
        self.assertEqual(delete_res.status_code, status.HTTP_200_OK)
        self.assertTrue(delete_res.data["success"])

        # Check DB
        self.assertFalse(Lead.objects.filter(pk=lead_id).exists())

    def test_user_cannot_delete_other_user_lead(self):
        # Create lead by self.user
        self.client.force_authenticate(user=self.user)
        create_res = self.client.post(self.leads_url, self.valid_lead_payload, format="json")
        lead_id = create_res.data["data"]["id"]

        # Create another user
        other_user = User.objects.create_user(
            email="otheragent@drdesigntech.com",
            password="OtherPassword@123",
            first_name="Other",
            last_name="Agent",
            role="LEAD_GEN",
            is_active=True,
            is_email_verified=True,
        )

        # Authenticate as other user and attempt delete
        self.client.force_authenticate(user=other_user)
        del_res = self.client.delete(f"/api/leads/{lead_id}/")
        self.assertEqual(del_res.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(del_res.data["success"])

        # Ensure lead still exists
        self.assertTrue(Lead.objects.filter(pk=lead_id).exists())


    def test_search_leads_by_name(self):
        self.client.force_authenticate(user=self.user)
        self.client.post(self.leads_url, self.valid_lead_payload, format="json")

        # Search by partial name
        response = self.client.get(f"{self.leads_url}?search=Aarav")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["success"])
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["data"][0]["client_full_name"], "Aarav Sharma")

    def test_search_leads_multi_token(self):
        self.client.force_authenticate(user=self.user)
        self.client.post(self.leads_url, self.valid_lead_payload, format="json")

        # Search across two different fields: name and city/address
        response = self.client.get(f"{self.leads_url}?search=Aarav Noida")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

    def test_filter_leads_by_status_and_category(self):
        self.client.force_authenticate(user=self.user)
        self.client.post(self.leads_url, self.valid_lead_payload, format="json")

        # Match status
        res1 = self.client.get(f"{self.leads_url}?status=Open")
        self.assertEqual(res1.status_code, status.HTTP_200_OK)
        self.assertEqual(res1.data["count"], 1)

        # Mismatch status
        res2 = self.client.get(f"{self.leads_url}?status=Closed")
        self.assertEqual(res2.status_code, status.HTTP_200_OK)
        self.assertEqual(res2.data["count"], 0)

    def test_search_leads_pagination(self):
        self.client.force_authenticate(user=self.user)
        self.client.post(self.leads_url, self.valid_lead_payload, format="json")

        # Paginated request
        response = self.client.get(f"{self.leads_url}?page=1&page_size=1")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("page", response.data)
        self.assertIn("total_pages", response.data)
        self.assertEqual(len(response.data["data"]), 1)



from erp.models import ScheduleCallback


class ScheduleCallbackAPITests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.callbacks_url = "/api/callbacks/"

        self.user = User.objects.create_user(
            email="callbackagent@drdesigntech.com",
            password="AgentPassword@123",
            first_name="Agent",
            last_name="Callback",
            role="LEAD_GEN",
            is_active=True,
            is_email_verified=True,
        )

        self.lead = Lead.objects.create(
            client_full_name="David Lune",
            client_email="david@fake.in",
            client_company_name="Fake Corp",
            client_website_address="https://fake.com",
            client_is="Domestic",
            country_name="India",
            client_full_address="Gurugram, Haryana",
            client_contact_number="+91 786678978",
            lead_type="Warm",
            project_category="E-commerce Website",
            requirement_description="We need a complete custom ERP solution with multi-role access control, lead pipeline tracking, and invoice generation modules.",
            status="Open",
            next_follow_up="No",
            lead_generated_from="Social Media",
            created_by=self.user,
        )

        self.valid_callback_payload = {
            "lead_id": self.lead.lead_id, # Testing formatted lead_id "DR-LEAD-XXXX"
            "phone": "+91 786678978",
            "date_time": "2026-11-10 14:30:00",
            "type": "Public",
            "notes": "Discuss custom ecommerce features and budget requirements.",
            "status": "Pending",
        }

    def test_schedule_callback_success(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.callbacks_url, self.valid_callback_payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data["success"])
        self.assertEqual(response.data["data"]["lead_ref"], self.lead.lead_id)
        self.assertEqual(response.data["data"]["client_name"], "David Lune")
        self.assertEqual(response.data["data"]["phone"], "+91 786678978")
        self.assertEqual(response.data["data"]["type"], "Public")

        # Verify DB
        callback = ScheduleCallback.objects.get(pk=response.data["data"]["id"])
        self.assertEqual(callback.lead, self.lead)
        self.assertEqual(callback.created_by, self.user)

    def test_schedule_callback_phone_auto_populated_if_omitted(self):
        self.client.force_authenticate(user=self.user)
        payload = self.valid_callback_payload.copy()
        payload.pop("phone") # Omit phone
        response = self.client.post(self.callbacks_url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Should auto-populate from lead.client_contact_number
        self.assertEqual(response.data["data"]["phone"], self.lead.client_contact_number)

    def test_list_and_search_callbacks(self):
        self.client.force_authenticate(user=self.user)
        self.client.post(self.callbacks_url, self.valid_callback_payload, format="json")

        # List all
        list_res = self.client.get(self.callbacks_url)
        self.assertEqual(list_res.status_code, status.HTTP_200_OK)
        self.assertTrue(list_res.data["success"])
        self.assertGreaterEqual(list_res.data["count"], 1)

        # Search by lead_id
        search_res = self.client.get(f"{self.callbacks_url}?search={self.lead.lead_id}")
        self.assertEqual(search_res.status_code, status.HTTP_200_OK)
        self.assertEqual(search_res.data["count"], 1)

    def test_filter_my_callbacks(self):
        self.client.force_authenticate(user=self.user)
        # Create callback by self.user
        self.client.post(self.callbacks_url, self.valid_callback_payload, format="json")

        # Create another user and another public callback
        other_user = User.objects.create_user(
            email="otheragent@drdesigntech.com",
            password="OtherPassword@123",
            first_name="Other",
            last_name="Agent",
            role="LEAD_GEN",
            is_active=True,
            is_email_verified=True,
        )
        ScheduleCallback.objects.create(
            lead=self.lead,
            phone="+91 9999999999",
            date_time="2026-11-15 10:00:00",
            type="Public",
            notes="Other agent callback",
            status="Pending",
            created_by=other_user,
        )

        # Whole team view (returns at least 2)
        res_all = self.client.get(self.callbacks_url)
        self.assertEqual(res_all.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(res_all.data["count"], 2)

        # My callbacks view (returns only callbacks by self.user)
        res_my = self.client.get(f"{self.callbacks_url}?scope=my")
        self.assertEqual(res_my.status_code, status.HTTP_200_OK)
        self.assertEqual(res_my.data["count"], 1)
        self.assertEqual(res_my.data["data"][0]["client_name"], "David Lune")

    def test_update_callback(self):
        self.client.force_authenticate(user=self.user)
        create_res = self.client.post(self.callbacks_url, self.valid_callback_payload, format="json")
        callback_id = create_res.data["data"]["id"]

        update_payload = {
            "status": "Completed",
            "notes": "Call finished. Client asked for written quote.",
        }
        patch_res = self.client.patch(f"{self.callbacks_url}{callback_id}/", update_payload, format="json")
        self.assertEqual(patch_res.status_code, status.HTTP_200_OK)
        self.assertTrue(patch_res.data["success"])
        self.assertEqual(patch_res.data["data"]["status"], "Completed")
        self.assertEqual(patch_res.data["data"]["notes"], "Call finished. Client asked for written quote.")

    def test_delete_callback(self):
        self.client.force_authenticate(user=self.user)
        create_res = self.client.post(self.callbacks_url, self.valid_callback_payload, format="json")
        callback_id = create_res.data["data"]["id"]

        del_res = self.client.delete(f"{self.callbacks_url}{callback_id}/")
        self.assertEqual(del_res.status_code, status.HTTP_200_OK)
        self.assertTrue(del_res.data["success"])
        self.assertFalse(ScheduleCallback.objects.filter(pk=callback_id).exists())


from erp.models import EmailCampaign


class EmailCampaignAPITests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.campaigns_url = "/api/campaigns/"

        # Create user
        self.user = User.objects.create_user(
            email="campaign_user@drdesigntech.com",
            password="StrongPassword@123",
            first_name="Ashish",
            last_name="Rawat",
            role="LEAD_GEN",
            is_active=True,
            is_email_verified=True,
        )

        # Create sample leads for audience matching
        self.lead1 = Lead.objects.create(
            client_full_name="David Lune",
            client_email="david@fake.in",
            client_company_name="Fake Co",
            client_is="Domestic",
            country_name="India",
            client_full_address="Gurugram",
            client_contact_number="+91 786678978",
            lead_type="Warm",
            project_category="E-commerce Website",
            requirement_description="Need complete custom ERP solution with multi-role access control.",
            status="Open",
            created_by=self.user,
        )

        self.lead2 = Lead.objects.create(
            client_full_name="John Smith",
            client_email="john@ukdesigns.com",
            client_company_name="UK Designs",
            client_is="International",
            country_name="United Kingdom",
            client_full_address="London",
            client_contact_number="+44 2079460912",
            lead_type="Hot",
            project_category="Web Development",
            requirement_description="Website revamp with modern stack and fast loading times.",
            status="In Progress",
            created_by=self.user,
        )

        self.lead_no_email = Lead.objects.create(
            client_full_name="No Email Client",
            client_email="",
            client_company_name="Offline Ltd",
            client_is="Domestic",
            country_name="India",
            client_full_address="Delhi",
            client_contact_number="+91 9988776655",
            lead_type="Cold",
            project_category="Web Development",
            requirement_description="Needs regular website maintenance without email contact.",
            status="Open",
            created_by=self.user,
        )

        self.lead_lost = Lead.objects.create(
            client_full_name="Lost Lead",
            client_email="lost@example.com",
            client_company_name="Lost Inc",
            client_is="Domestic",
            country_name="India",
            client_full_address="Mumbai",
            client_contact_number="+91 9876543210",
            lead_type="Hot",
            project_category="Web Development",
            requirement_description="Lost client proposal due to budget constraints.",
            status="Lost",
            created_by=self.user,
        )

        self.valid_campaign_payload = {
            "campaign_name": "Diwali offer — UK design leads",
            "lead_type": "Any",
            "category": "Any",
            "country": "Any",
            "client_is": "Any",
            "sales_status": "Any (except Lost/Closed)",
            "subject": "Exclusive Design & ERP Offers For You",
            "message": "Hi {name},\n\nWe have exclusive Diwali deals for {company}.\n\nRegards,\nAshish\nDR. DESIGN PVT. LTD.",
        }

    def test_unauthenticated_request_rejected(self):
        res = self.client.get(self.campaigns_url)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_campaign(self):
        self.client.force_authenticate(user=self.user)
        res = self.client.post(self.campaigns_url, self.valid_campaign_payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertTrue(res.data["success"])
        self.assertEqual(res.data["data"]["campaign_name"], "Diwali offer — UK design leads")
        self.assertTrue(res.data["data"]["campaign_id"].startswith("CAMP-"))
        self.assertEqual(res.data["data"]["created_by_name"], "Ashish Rawat")

    def test_create_campaign_filtered_audience(self):
        self.client.force_authenticate(user=self.user)
        payload = self.valid_campaign_payload.copy()
        payload["country"] = "United Kingdom"
        payload["lead_type"] = "Hot"
        res = self.client.post(self.campaigns_url, payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertTrue(res.data["success"])
        self.assertEqual(res.data["data"]["country"], "United Kingdom")

    def test_list_and_search_campaigns(self):
        self.client.force_authenticate(user=self.user)
        self.client.post(self.campaigns_url, self.valid_campaign_payload, format="json")

        list_res = self.client.get(self.campaigns_url)
        self.assertEqual(list_res.status_code, status.HTTP_200_OK)
        self.assertTrue(list_res.data["success"])
        self.assertEqual(list_res.data["count"], 1)

        # Search by keyword
        search_res = self.client.get(f"{self.campaigns_url}?search=Diwali")
        self.assertEqual(search_res.status_code, status.HTTP_200_OK)
        self.assertEqual(search_res.data["count"], 1)

    def test_update_campaign(self):
        self.client.force_authenticate(user=self.user)
        create_res = self.client.post(self.campaigns_url, self.valid_campaign_payload, format="json")
        camp_id = create_res.data["data"]["id"]

        patch_res = self.client.patch(
            f"{self.campaigns_url}{camp_id}/",
            {"subject": "Updated Diwali Offer Subject", "status": "Scheduled"},
            format="json",
        )
        self.assertEqual(patch_res.status_code, status.HTTP_200_OK)
        self.assertTrue(patch_res.data["success"])
        self.assertEqual(patch_res.data["data"]["subject"], "Updated Diwali Offer Subject")
        self.assertEqual(patch_res.data["data"]["status"], "Scheduled")

    def test_delete_campaign(self):
        self.client.force_authenticate(user=self.user)
        create_res = self.client.post(self.campaigns_url, self.valid_campaign_payload, format="json")
        camp_id = create_res.data["data"]["id"]

        del_res = self.client.delete(f"{self.campaigns_url}{camp_id}/")
        self.assertEqual(del_res.status_code, status.HTTP_200_OK)
        self.assertTrue(del_res.data["success"])
        self.assertFalse(EmailCampaign.objects.filter(pk=camp_id).exists())

    def test_campaign_leads_endpoint(self):
        self.client.force_authenticate(user=self.user)
        create_res = self.client.post(self.campaigns_url, self.valid_campaign_payload, format="json")
        camp_id = create_res.data["data"]["id"]

        leads_res = self.client.get(f"{self.campaigns_url}{camp_id}/leads/")
        self.assertEqual(leads_res.status_code, status.HTTP_200_OK)
        self.assertTrue(leads_res.data["success"])
        self.assertEqual(leads_res.data["matching_leads_count"], 2)
        self.assertEqual(len(leads_res.data["data"]), 2)


class LeadGenerationReportTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.report_url = "/api/reports/lead-generation/"

        self.user = User.objects.create_user(
            email="report_user@drdesigntech.com",
            password="StrongPassword@123",
            first_name="Ashish",
            last_name="Rawat",
            role="ADMIN",
        )

        # Create sample leads
        Lead.objects.create(
            client_full_name="Alpha Tech",
            client_email="alpha@tech.com",
            client_company_name="Alpha Tech Ltd",
            country_name="India",
            client_is="Domestic",
            client_full_address="Connaught Place, New Delhi",
            client_contact_number="+919876543210",
            lead_type="Hot",
            project_category="Graphic Designing",
            requirement_description="Corporate branding",
            status="In Progress",
            lead_generated_from="Calling",
            created_by=self.user,
        )

        Lead.objects.create(
            client_full_name="Beta Innovations",
            client_email="beta@innovations.co.uk",
            client_company_name="Beta Innovations UK",
            country_name="United Kingdom",
            client_is="International",
            client_full_address="London, UK",
            client_contact_number="+442079460999",
            lead_type="Warm",
            project_category="Website Design & Development",
            requirement_description="E-commerce portal",
            status="Converted",
            lead_generated_from="Email",
            created_by=self.user,
        )

    def test_unauthenticated_report_denied(self):
        res = self.client.get(self.report_url)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authenticated_get_report(self):
        self.client.force_authenticate(user=self.user)
        res = self.client.get(self.report_url)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(res.data["success"])
        data = res.data["data"]

        # Check summary
        summary = data["summary"]
        self.assertEqual(summary["leads_generated"], 2)
        self.assertEqual(summary["hot_leads"], 1)
        self.assertEqual(summary["worked_upon"], 2)
        self.assertEqual(summary["converted"], 1)
        self.assertEqual(summary["conversion_pct"], 50.0)

        # Check leads_per_day
        self.assertTrue(len(data["leads_per_day"]) >= 1)

        # Check executive performance
        self.assertEqual(len(data["by_executive"]), 1)
        self.assertEqual(data["by_executive"][0]["executive"], "Ashish Rawat")
        self.assertEqual(data["by_executive"][0]["generated"], 2)

        # Check breakdowns
        self.assertTrue(any(c["name"] == "Graphic Designing" for c in data["by_project_category"]))
        self.assertTrue(any(s["name"] == "Calling" for s in data["by_source"]))
        self.assertTrue(any(c["name"] == "India" for c in data["by_country"]))
        self.assertTrue(any(t["name"] == "Hot" for t in data["by_lead_type"]))
        self.assertTrue(len(data["by_call_status"]) > 0)
        self.assertEqual(len(data["passed_to_executive"]), 1)

    def test_report_date_filtering(self):
        self.client.force_authenticate(user=self.user)
        today = timezone.now().date().strftime("%Y-%m-%d")
        res = self.client.get(f"{self.report_url}?date_from={today}&date_to={today}")

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(res.data["success"])
        self.assertEqual(res.data["data"]["summary"]["leads_generated"], 2)

    def test_reports_web_view(self):
        self.client.force_login(self.user)
        res = self.client.get("/reports/")
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertContains(res, "Lead Generation Report")

