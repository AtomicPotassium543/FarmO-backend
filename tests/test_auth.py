import copy
import os
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError
from starlette.requests import Request

from routes import auth


class Codes:
    def __init__(self):
        self.rows = {}

    def matches(self, row, query):
        for key, expected in query.items():
            actual = row.get(key)
            if isinstance(expected, dict):
                for op, value in expected.items():
                    if actual is None or not {"$lte": lambda: actual <= value, "$lt": lambda: actual < value,
                                              "$gt": lambda: actual > value}[op]():
                        return False
            elif actual != expected:
                return False
        return True

    async def update_one(self, query, update, upsert=False):
        row = self.rows.get(query["_id"])
        if row and not self.matches(row, query):
            if upsert:
                raise DuplicateKeyError("duplicate")
            return SimpleNamespace(modified_count=0)
        if row is None:
            if not upsert:
                return SimpleNamespace(modified_count=0)
            row = self.rows[query["_id"]] = {"_id": query["_id"]}
        row.update(update.get("$set", {}))
        return SimpleNamespace(modified_count=1)

    async def find_one_and_update(self, query, update, **kwargs):
        row = self.rows.get(query["_id"])
        if not row or not self.matches(row, query):
            return None
        row["attempts"] += update["$inc"]["attempts"]
        return copy.deepcopy(row)


class AuthTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.codes = Codes()
        self.enterContext(patch.object(auth, "otp_codes", self.codes))
        self.enterContext(patch.dict(os.environ, {"APP_ENV": "production", "OTP_DELIVERY": "provider",
                                                   "JWT_SECRET": "test-secret-at-least-thirty-two-bytes",
                                                   "SMTP_HOST": "", "SMTP_USERNAME": "", "SMTP_PASSWORD": "",
                                                   "TWILIO_ACCOUNT_SID": "", "TWILIO_AUTH_TOKEN": "", "TWILIO_FROM_NUMBER": ""}))
        self.email = "tests@example.com"

    async def assert_http(self, status, call):
        with self.assertRaises(HTTPException) as error:
            await call
        self.assertEqual(error.exception.status_code, status)

    async def test_codes_single_use_and_hashed(self):
        code = await auth.create_otp(self.email, "verify-email", self.email)
        self.assertRegex(code, r"^\d{6}$")
        row = self.codes.rows[f"{self.email}:verify-email"]
        self.assertNotEqual(row["code_hash"], code)
        await auth.consume_otp(self.email, code, "verify-email", self.email)
        await self.assert_http(410, auth.consume_otp(self.email, code, "verify-email", self.email))

    async def test_codes_expire(self):
        code = await auth.create_otp(self.email, "reset", self.email)
        self.codes.rows[f"{self.email}:reset"]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        await self.assert_http(410, auth.consume_otp(self.email, code, "reset", self.email))

    async def test_five_attempt_limit(self):
        code = await auth.create_otp(self.email, "reset", self.email)
        wrong = "000001" if code == "000000" else "000000"
        for _ in range(5):
            await self.assert_http(422, auth.consume_otp(self.email, wrong, "reset", self.email))
        await self.assert_http(410, auth.consume_otp(self.email, code, "reset", self.email))

    async def test_resend_throttle_and_replacement(self):
        old = await auth.create_otp(self.email, "reset", self.email)
        await self.assert_http(429, auth.create_otp(self.email, "reset", self.email))
        self.codes.rows[f"{self.email}:reset"]["created_at"] -= timedelta(minutes=2)
        with patch.object(auth.secrets, "randbelow", return_value=(int(old) + 1) % 1000000):
            new = await auth.create_otp(self.email, "reset", self.email)
        await self.assert_http(422, auth.consume_otp(self.email, old, "reset", self.email))
        await auth.consume_otp(self.email, new, "reset", self.email)

    async def test_code_bound_to_purpose_and_phone(self):
        code = await auth.create_otp(self.email, "verify-phone", "+15550123456")
        await self.assert_http(410, auth.consume_otp(self.email, code, "reset", self.email))
        await self.assert_http(410, auth.consume_otp(self.email, code, "verify-phone", "+15550987654"))

    async def test_production_never_exposes_code_without_credentials(self):
        with patch.dict(os.environ, {"OTP_DELIVERY": "console"}):
            await self.assert_http(503, auth.deliver_otp(self.email, "123456", "verify-email"))
        with patch.dict(os.environ, {"APP_ENV": "development"}):
            await self.assert_http(503, auth.deliver_otp(self.email, "123456", "verify-email"))
        with patch.dict(os.environ, {"APP_ENV": "development", "OTP_DELIVERY": "console"}):
            self.assertEqual(await auth.deliver_otp(self.email, "123456", "verify-email"), "123456")

    async def test_smtp_delivery_hides_code_and_uses_configured_sender(self):
        with patch.dict(os.environ, {"SMTP_HOST": "smtp.example.com", "SMTP_USERNAME": "test", "SMTP_PASSWORD": "test",
                                     "SMTP_FROM_EMAIL": "farmo@example.com", "SMTP_PORT": "465"}), patch.object(auth, "smtp_send", new_callable=AsyncMock) as send:
            self.assertIsNone(await auth.deliver_otp(self.email, "123456", "verify-email"))
            message = send.call_args.args[0]
            self.assertEqual(message["From"], "farmo@example.com")
            self.assertIn("123456", message.get_content())
            self.assertTrue(send.call_args.kwargs["use_tls"])

    async def test_twilio_delivery_hides_code(self):
        client = AsyncMock()
        client.post.return_value = MagicMock()
        client.__aenter__.return_value = client
        with patch.dict(os.environ, {"TWILIO_ACCOUNT_SID": "ACtest", "TWILIO_AUTH_TOKEN": "secret", "TWILIO_FROM_NUMBER": "+15550123456"}), patch.object(auth.httpx, "AsyncClient", return_value=client):
            self.assertIsNone(await auth.deliver_otp("+15550987654", "123456", "verify-phone"))
            self.assertEqual(client.post.call_args.kwargs["data"]["To"], "+15550987654")

    async def test_failed_signup_delivery_does_not_create_ghost_account(self):
        users = AsyncMock()
        users.find_one.return_value = None
        with patch.object(auth, "users", users):
            await self.assert_http(503, auth.register(auth.RegisterRequest(email=self.email, password="Password123")))
        users.insert_one.assert_not_called()
        self.assertTrue(self.codes.rows[f"{self.email}:verify-email"]["consumed"])

    async def test_signup_does_not_auto_verify(self):
        users = AsyncMock()
        users.find_one.return_value = None
        with patch.object(auth, "users", users), patch.object(auth, "issue_tokens", new_callable=AsyncMock, return_value={}), patch.dict(os.environ, {"APP_ENV": "development", "OTP_DELIVERY": "console"}):
            result = await auth.register(auth.RegisterRequest(email=self.email, password="Password123"))
            self.assertFalse(result.data["user"]["email_verified"])
            self.assertRegex(result.data["dev_code"], r"^\d{6}$")
            self.assertTrue(auth.password_hasher.verify("Password123", users.insert_one.call_args.args[0]["password_hash"]))

    async def test_verification_requires_matching_session(self):
        request = Request({"type": "http", "headers": []})
        await self.assert_http(401, auth.request_otp(auth.OtpRequest(email=self.email), request))
        users = AsyncMock()
        users.find_one.return_value = None
        with patch.object(auth, "get_access_token_payload", return_value={"sub": "other"}), patch.object(auth, "users", users):
            await self.assert_http(403, auth.verify_otp(auth.OtpVerifyRequest(email=self.email, code="123456"), request))

    async def test_reset_does_not_enumerate_accounts(self):
        users = AsyncMock()
        request = Request({"type": "http", "headers": []})
        with patch.object(auth, "users", users):
            users.find_one.return_value = None
            unknown = await auth.request_otp(auth.OtpRequest(email=self.email, purpose="reset"), request)
            users.find_one.return_value = {"email": self.email}
            known = await auth.request_otp(auth.OtpRequest(email=self.email, purpose="reset"), request)
            self.assertEqual(unknown.data, known.data)

    async def test_viewer_backend_cannot_write(self):
        from bson import ObjectId
        from routes import project
        project_id = ObjectId()
        collection = AsyncMock()
        collection.find_one.return_value = {"_id": project_id, "owner_id": "owner", "collaborators": ["viewer"]}
        with patch.object(project, "projects", collection):
            self.assertIsNotNone(await project.get_project(str(project_id), "viewer"))
            await self.assert_http(403, project.get_project(str(project_id), "viewer", owner_only=True))

    async def test_account_deletion_cascades_only_owned_data(self):
        from bson import ObjectId
        project_id = ObjectId()
        async def owned_projects():
            yield {"_id": project_id}
        collections = {name: AsyncMock() for name in ("users", "sessions", "email_verifications", "otp_codes", "password_resets", "projects", "farms", "plants", "advices", "risks")}
        collections["users"].find_one.return_value = {"_id": "owner", "email": self.email}
        collections["projects"].find = MagicMock(return_value=owned_projects())
        with patch.multiple(auth, **collections), patch.object(auth, "get_access_token_payload", return_value={"sub": "owner"}):
            await auth.delete_current_user(Request({"type": "http", "headers": []}))
        for name in ("farms", "plants"):
            collections[name].delete_many.assert_awaited_once_with({"project_id": {"$in": [str(project_id)]}})
        collections["users"].delete_one.assert_awaited_once_with({"_id": "owner"})
        collections["sessions"].delete_many.assert_awaited_once_with({"user_id": "owner"})
        for name in ("advices", "risks"):
            collections[name].delete_many.assert_awaited_once_with({"created_by": "owner"})

    async def test_reset_changes_password_and_revokes_refresh_sessions(self):
        code = await auth.create_otp(self.email, "reset", self.email)
        users, sessions = AsyncMock(), AsyncMock()
        users.find_one.return_value = {"_id": "user", "email": self.email}
        with patch.object(auth, "users", users), patch.object(auth, "sessions", sessions):
            await auth.reset_password(auth.PasswordResetRequest(email=self.email, code=code, password="Changed123"))
            stored = users.update_one.call_args.args[1]["$set"]["password_hash"]
            self.assertTrue(auth.password_hasher.verify("Changed123", stored))
            sessions.update_many.assert_awaited_once()
            await self.assert_http(410, auth.reset_password(auth.PasswordResetRequest(email=self.email, code=code, password="Changed456")))


if __name__ == "__main__":
    unittest.main()
