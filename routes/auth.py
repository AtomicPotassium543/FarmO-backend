
import os
import secrets
import logging
import hashlib
import hmac
import re
import httpx
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from authlib.integrations.starlette_client import OAuth

from aiosmtplib import send as smtp_send
from email.message import EmailMessage


# MongoDB collections (provided by your database module)
from database import (
    users,
    sessions,
    email_verifications,
    otp_codes,
    password_resets,
    projects,
    farms,
    plants,
    advices,
    risks,
)

# Existing JWT helpers
from utils.auth import password_hash, create_token_pair, decode_token, token_fingerprint
from utils.responses import ErrorResponse, SuccessResponse

password_hasher = PasswordHash.recommended()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

FRONTEND_URL = os.getenv("FRONTEND_URL")
BACKEND_URL = os.getenv("BACKEND_URL")

VERIFICATION_EXPIRY = timedelta(minutes=30)
OTP_EXPIRY = timedelta(minutes=10)
OTP_PURPOSES = {"verify-email", "verify-phone", "reset"}

oauth = OAuth()

oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url=(
        "https://accounts.google.com/.well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid email profile"
    }
)

oauth.register(
    name="facebook",
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    authorize_url="https://www.facebook.com/v23.0/dialog/oauth",
    access_token_url="https://graph.facebook.com/v23.0/oauth/access_token",
    api_base_url="https://graph.facebook.com/",
    client_kwargs={
        "scope": "email public_profile"
    }
)

oauth.register(
    name="yahoo",
    client_id=os.getenv("YAHOO_CLIENT_ID"),
    client_secret=os.getenv("YAHOO_CLIENT_SECRET"),
    authorize_url="https://api.login.yahoo.com/oauth2/request_auth",
    access_token_url="https://api.login.yahoo.com/oauth2/get_token",
    api_base_url="https://api.login.yahoo.com/",
    client_kwargs={
        "scope": "openid email profile"
    }
)


# --------------------------------------------------
# Request / Response schemas
# --------------------------------------------------

class AuthRoute(APIRoute):
    def get_route_handler(self):
        original_handler = super().get_route_handler()

        async def wrapped_handler(request: Request):
            try:
                return await original_handler(request)
            except HTTPException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content=ErrorResponse(error=str(exc.detail)).model_dump(),
                    headers=exc.headers
                )
            except RequestValidationError:
                return JSONResponse(
                    status_code=422,
                    content=ErrorResponse(
                        error="Request validation failed."
                    ).model_dump()
                )
            except Exception:
                logging.getLogger(__name__).exception(
                    "Unhandled error in authentication route %s",
                    request.url.path
                )
                return JSONResponse(
                    status_code=500,
                    content=ErrorResponse(
                        error="Internal server error."
                    ).model_dump()
                )

        return wrapped_handler


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    route_class=AuthRoute
)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    username: str | None = None
    name: str | None = None
    phone: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class OtpRequest(BaseModel):
    email: EmailStr
    purpose: str = "verify-email"


class OtpVerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^[0-9]{6}$")
    purpose: str = "verify-email"


class PasswordResetRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^[0-9]{6}$")
    password: str = Field(min_length=6, max_length=128)


# --------------------------------------------------
# Token / Session management
# --------------------------------------------------

async def issue_tokens(user_id: str):
    """
    Generate a token pair and register its refresh session
    in MongoDB.
    """

    access_token, refresh_token, jti = create_token_pair(user_id)

    refresh_payload = decode_token(refresh_token)

    await sessions.insert_one({
        "jti": jti,
        "user_id": user_id,
        "token_hash": token_fingerprint(refresh_token),
        "expires_at": datetime.fromtimestamp(
            refresh_payload["exp"],
            timezone.utc
        ),
        "created_at": datetime.now(timezone.utc),
        "revoked": False
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


async def revoke_session(refresh_token: str):
    """
    Validate a refresh token and revoke its associated session.
    """

    try:
        payload = decode_token(refresh_token)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token."
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=401,
            detail="A refresh token is required."
        )

    session = await sessions.find_one({
        "jti": payload["jti"],
        "token_hash": token_fingerprint(refresh_token),
        "revoked": False
    })

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Session is invalid or already revoked."
        )

    await sessions.update_one(
        {"jti": payload["jti"]},
        {
            "$set": {
                "revoked": True,
                "revoked_at": datetime.now(timezone.utc)
            }
        }
    )


# --------------------------------------------------
# Email verification
# --------------------------------------------------

async def send_verification_email(email: str, token: str):
    """
    Send an email containing the verification link.
    """

    verification_url = (
        f"{FRONTEND_URL}/verify-email?token={token}"
    )

    message = EmailMessage()
    message["Subject"] = "Verify your Farmo account"
    message["From"] = os.getenv("SMTP_FROM")
    message["To"] = email

    message.set_content(
        f"""
        Welcome to Farmo!

        Please verify your email address using the link below:

        {verification_url}

        This link expires in 30 minutes.
        """
    )

    smtp_user = os.getenv("SMTP_USERNAME")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    if not smtp_user or not smtp_pass:
        logging.getLogger(__name__).info("SMTP credentials not configured; skipping email delivery.")
        return

    try:
        await smtp_send(
            message,
            hostname=os.getenv("SMTP_HOST", "smtp.gmail.com"),
            port=int(os.getenv("SMTP_PORT", "587")),
            username=smtp_user,
            password=smtp_pass,
            start_tls=True
        )
    except Exception as e:
        logging.getLogger(__name__).warning("Failed to send verification email: %s", e)


async def create_email_verification(email: str):
    """
    Create a new single-use email verification token.
    """

    token = secrets.token_urlsafe(32)

    await email_verifications.delete_many({
        "email": email
    })

    await email_verifications.insert_one({
        "email": email,
        "token_hash": token_fingerprint(token),
        "expires_at": (
            datetime.now(timezone.utc) + VERIFICATION_EXPIRY
        ),
        "created_at": datetime.now(timezone.utc)
    })

    await send_verification_email(email, token)


# --------------------------------------------------
# Six-digit one-time codes (email / phone / reset)
# --------------------------------------------------

def development_codes() -> bool:
    return os.getenv("APP_ENV") == "development" and os.getenv("OTP_DELIVERY") == "console"


def otp_fingerprint(email: str, purpose: str, destination: str, code: str) -> str:
    return hmac.new(os.environ["JWT_SECRET"].encode(), f"{email}:{purpose}:{destination}:{code}".encode(), hashlib.sha256).hexdigest()


async def create_otp(email: str, purpose: str, destination: str) -> str:
    now = datetime.now(timezone.utc)
    code = f"{secrets.randbelow(1_000_000):06d}"
    try:
        await otp_codes.update_one(
            {"_id": f"{email}:{purpose}", "created_at": {"$lte": now - timedelta(seconds=60)}},
            {"$set": {
                "email": email, "purpose": purpose, "destination": destination,
                "code_hash": otp_fingerprint(email, purpose, destination, code),
                "expires_at": now + OTP_EXPIRY, "created_at": now,
                "consumed": False, "attempts": 0,
            }},
            upsert=True,
        )
    except DuplicateKeyError:
        raise HTTPException(status_code=429, detail="Wait one minute before requesting another code.")
    return code


async def consume_otp(email: str, code: str, purpose: str, destination: str) -> None:
    challenge = await otp_codes.find_one_and_update(
        {"_id": f"{email}:{purpose}", "destination": destination, "consumed": False,
         "expires_at": {"$gt": datetime.now(timezone.utc)}, "attempts": {"$lt": 5}},
        {"$inc": {"attempts": 1}}, return_document=ReturnDocument.AFTER,
    )
    if not challenge:
        raise HTTPException(status_code=410, detail="Code expired, already used, or too many attempts. Request a new one.")
    if not hmac.compare_digest(challenge["code_hash"], otp_fingerprint(email, purpose, destination, code)):
        raise HTTPException(status_code=422, detail="That code is not correct.")
    result = await otp_codes.update_one(
        {"_id": challenge["_id"], "code_hash": challenge["code_hash"], "consumed": False},
        {"$set": {"consumed": True}},
    )
    if not result.modified_count:
        raise HTTPException(status_code=410, detail="Code already used. Request a new one.")


async def deliver_otp(destination: str, code: str, purpose: str) -> str | None:
    if development_codes():
        return code
    text = f"Your Farmo code is {code}. It expires in 10 minutes. If you did not request this, ignore it."
    if purpose == "verify-phone":
        sid, token, sender = (os.getenv(key) for key in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER"))
        if not all((sid, token, sender)):
            raise HTTPException(status_code=503, detail="SMS delivery is not configured. Verify by email instead.")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(
                    f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                    auth=(sid, token), data={"To": destination, "From": sender, "Body": text},
                )
                response.raise_for_status()
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="SMS could not be sent. Please try again later.")
        return None
    sender = os.getenv("SMTP_FROM_EMAIL") or os.getenv("SMTP_FROM") or os.getenv("SMTP_USERNAME")
    if not all((os.getenv("SMTP_HOST"), os.getenv("SMTP_USERNAME"), os.getenv("SMTP_PASSWORD"), sender)):
        raise HTTPException(status_code=503, detail="Email delivery is not configured. Please contact the administrator.")
    message = EmailMessage()
    message["Subject"] = "Your Farmo password reset code" if purpose == "reset" else "Your Farmo verification code"
    message["From"], message["To"] = sender, destination
    message.set_content(text)
    port = int(os.getenv("SMTP_PORT", "587"))
    try:
        await smtp_send(message, hostname=os.environ["SMTP_HOST"], port=port,
                        username=os.environ["SMTP_USERNAME"], password=os.environ["SMTP_PASSWORD"],
                        use_tls=port == 465, start_tls=port != 465, timeout=15)
    except Exception:
        raise HTTPException(status_code=503, detail="Email could not be sent. Please try again later.")
    return None


async def send_otp(email: str, purpose: str, destination: str) -> str | None:
    code = await create_otp(email, purpose, destination)
    try:
        return await deliver_otp(destination, code, purpose)
    except HTTPException:
        await otp_codes.update_one({"_id": f"{email}:{purpose}"}, {"$set": {"consumed": True}})
        raise


# --------------------------------------------------
# Registration
# --------------------------------------------------

@router.post("/register", response_model=SuccessResponse)
async def register(data: RegisterRequest):
    """
    Register a new account and initiate email verification.
    """

    email = data.email.lower()
    existing_user = await users.find_one({"email": email})

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists."
        )

    user_id = str(uuid4())
    username = data.username or (data.name and data.name.lower().replace(" ", "_")) or data.email.split("@")[0]
    dev_code = await send_otp(email, "verify-email", email)

    user_document = {
        "_id": user_id,
        "username": username,
        "name": data.name or username,
        "phone": data.phone or "",
        "email": email,
        "password_hash": password_hasher.hash(data.password),
        "email_verified": False,
        "auth_providers": ["password"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }

    await users.insert_one(user_document)

    token_data = await issue_tokens(user_id)
    token_data["dev_code"] = dev_code
    token_data["user"] = {
        "id": user_id,
        "name": user_document["name"],
        "username": user_document["username"],
        "email": user_document["email"],
        "phone": user_document["phone"],
        "email_verified": user_document["email_verified"],
        "phone_verified": False,
        "auth_providers": ["password"]
    }

    return SuccessResponse(
        data=token_data
    )


# --------------------------------------------------
# Login
# --------------------------------------------------

@router.post("/login", response_model=SuccessResponse)
async def login(data: LoginRequest):
    """
    Authenticate an existing account and issue tokens.
    """

    user = await users.find_one({
        "email": data.email
    })

    if not user or not user.get("password_hash"):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    password_valid = password_hasher.verify(
        data.password,
        user["password_hash"]
    )

    if not password_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    token_data = await issue_tokens(user["_id"])
    token_data["user"] = {
        "id": user["_id"],
        "name": user.get("name") or user.get("username", "Farmo User"),
        "username": user.get("username"),
        "email": user.get("email"),
        "phone": user.get("phone", ""),
        "email_verified": user.get("email_verified", True),
        "phone_verified": user.get("phone_verified", False),
        "auth_providers": user.get("auth_providers", ["password"])
    }
    return SuccessResponse(data=token_data)


# --------------------------------------------------
# Logout
# --------------------------------------------------

@router.post("/logout", response_model=SuccessResponse)
async def logout(data: RefreshRequest):
    """
    Log out of the current session by revoking its refresh token.
    """

    await revoke_session(data.refresh_token)

    return SuccessResponse(data={"message": "Successfully logged out."})


# --------------------------------------------------
# Refresh the token pair
# --------------------------------------------------

@router.post("/refresh", response_model=SuccessResponse)
async def refresh(data: RefreshRequest):
    """
    Exchange a valid, unrevoked refresh token for a fresh token pair.
    """

    try:
        payload = decode_token(data.refresh_token)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="A refresh token is required.")

    session = await sessions.find_one({
        "jti": payload["jti"],
        "token_hash": token_fingerprint(data.refresh_token),
        "revoked": False
    })

    if not session:
        raise HTTPException(status_code=401, detail="Session is invalid or already revoked.")

    await sessions.update_one(
        {"jti": payload["jti"]},
        {"$set": {"revoked": True, "revoked_at": datetime.now(timezone.utc)}}
    )

    return SuccessResponse(data=await issue_tokens(payload["sub"]))


def get_access_token_payload(request: Request) -> dict:
    authorization = request.headers.get("Authorization")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required."
        )

    access_token = authorization.split(" ", 1)[1]

    try:
        payload = decode_token(access_token)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token."
        )

    if payload.get("type") != "access" or not payload.get("sub"):
        raise HTTPException(
            status_code=401,
            detail="A valid access token is required."
        )

    return payload


def format_profile(user: dict) -> dict:
    return {
        "id": user["_id"],
        "name": user.get("name") or user.get("username", "Farmo User"),
        "username": user.get("username"),
        "email": user.get("email"),
        "phone": user.get("phone", ""),
        "jobTitle": user.get("job_title", "Farm owner"),
        "email_verified": user.get("email_verified", False),
        "phone_verified": user.get("phone_verified", False),
        "auth_providers": user.get("auth_providers", [])
    }


@router.get("/me", response_model=SuccessResponse)
async def get_current_user(request: Request):
    """Return the authenticated user's public profile."""
    payload = get_access_token_payload(request)
    user = await users.find_one({"_id": payload["sub"]})

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Account not found."
        )

    return SuccessResponse(data=format_profile(user))


class ProfileUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    phone: str | None = Field(default=None, max_length=32)
    jobTitle: str | None = Field(default=None, max_length=80)


@router.patch("/me", response_model=SuccessResponse)
async def update_current_user(data: ProfileUpdateRequest, request: Request):
    """Update the profile fields the account screen can edit."""
    payload = get_access_token_payload(request)

    updates: dict[str, Any] = {}
    if data.name is not None:
        updates["name"] = data.name.strip()
    if data.phone is not None:
        current = await users.find_one({"_id": payload["sub"]})
        updates["phone"] = data.phone.strip()
        if current and current.get("phone") != updates["phone"]:
            updates["phone_verified"] = False
            await otp_codes.delete_many({"email": current["email"], "purpose": "verify-phone"})
    if data.jobTitle is not None:
        updates["job_title"] = data.jobTitle.strip()

    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided.")

    updates["updated_at"] = datetime.now(timezone.utc)
    await users.update_one({"_id": payload["sub"]}, {"$set": updates})

    user = await users.find_one({"_id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=404, detail="Account not found.")

    return SuccessResponse(data=format_profile(user))


@router.post("/logout-all", response_model=SuccessResponse)
async def logout_all(request: Request):
    """
    Revoke every active refresh session belonging to the
    authenticated user.
    """

    payload = get_access_token_payload(request)

    await sessions.update_many(
        {
            "user_id": payload["sub"],
            "revoked": False
        },
        {
            "$set": {
                "revoked": True,
                "revoked_at": datetime.now(timezone.utc)
            }
        }
    )

    return SuccessResponse(data={"message": "All sessions have been revoked."})


# --------------------------------------------------
# One-time codes: request, verify, password reset
# --------------------------------------------------

async def otp_user(request: Request, email: str) -> dict:
    payload = get_access_token_payload(request)
    user = await users.find_one({"_id": payload["sub"], "email": email})
    if not user:
        raise HTTPException(status_code=403, detail="Verify only the account you are signed in to.")
    return user


def otp_destination(user: dict, purpose: str) -> str:
    if purpose != "verify-phone":
        return user["email"]
    phone = re.sub(r"[\s()-]", "", user.get("phone", ""))
    if not re.fullmatch(r"\+[1-9][0-9]{6,14}", phone):
        raise HTTPException(status_code=422, detail="Save a phone number with its +country code before verifying.")
    return phone


@router.post("/otp/request", response_model=SuccessResponse)
async def request_otp(data: OtpRequest, request: Request):
    if data.purpose not in OTP_PURPOSES:
        raise HTTPException(status_code=422, detail="Unknown code purpose.")
    email = data.email.lower()
    if data.purpose == "reset":
        user = await users.find_one({"email": email})
        dev_code = None
        if user:
            try:
                dev_code = await send_otp(email, "reset", email)
            except HTTPException as exc:
                if exc.status_code not in (429, 503):
                    raise
        return SuccessResponse(data={"message": "If the account exists, a reset code will be sent.", "dev_code": dev_code})
    user = await otp_user(request, email)
    dev_code = await send_otp(email, data.purpose, otp_destination(user, data.purpose))
    return SuccessResponse(data={"sent": True, "dev_code": dev_code})


@router.post("/otp/verify", response_model=SuccessResponse)
async def verify_otp(data: OtpVerifyRequest, request: Request):
    if data.purpose not in {"verify-email", "verify-phone"}:
        raise HTTPException(status_code=422, detail="Use the password reset endpoint for reset codes.")
    email = data.email.lower()
    user = await otp_user(request, email)
    await consume_otp(email, data.code, data.purpose, otp_destination(user, data.purpose))
    field = "phone_verified" if data.purpose == "verify-phone" else "email_verified"
    query = {"_id": user["_id"]}
    if field == "phone_verified":
        query["phone"] = user["phone"]
    result = await users.update_one(query, {"$set": {field: True, "updated_at": datetime.now(timezone.utc)}})
    if not result.matched_count:
        raise HTTPException(status_code=409, detail="Contact details changed. Request a new code.")
    user[field] = True
    return SuccessResponse(data={"user": format_profile(user)})


@router.post("/password/reset", response_model=SuccessResponse)
async def reset_password(data: PasswordResetRequest):
    """Set a new password using a valid reset code, then revoke existing sessions."""
    email = data.email.lower()
    await consume_otp(email, data.code, "reset", email)

    user = await users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="No Farmo account matches that email address.")

    await users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "password_hash": password_hasher.hash(data.password),
            "email_verified": True,
            "updated_at": datetime.now(timezone.utc)
        }}
    )
    await sessions.update_many(
        {"user_id": user["_id"], "revoked": False},
        {"$set": {"revoked": True, "revoked_at": datetime.now(timezone.utc)}}
    )
    return SuccessResponse(data={"message": "Password updated. Sign in with your new password."})


# --------------------------------------------------
# Account deletion
# --------------------------------------------------

@router.delete("/me", response_model=SuccessResponse)
async def delete_current_user(request: Request):
    """Delete the authenticated account and everything it owns."""
    payload = get_access_token_payload(request)
    user_id = payload["sub"]

    user = await users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Account not found.")

    owner_ids: list[Any] = [user_id]
    if ObjectId.is_valid(user_id):
        owner_ids.append(ObjectId(user_id))

    project_ids = [
        str(project["_id"])
        async for project in projects.find({"owner_id": {"$in": owner_ids}}, {"_id": 1})
    ]
    if project_ids:
        await plants.delete_many({"project_id": {"$in": project_ids}})
        await farms.delete_many({"project_id": {"$in": project_ids}})
        await projects.delete_many({
            "_id": {"$in": [ObjectId(pid) for pid in project_ids if ObjectId.is_valid(pid)]}
        })

    await advices.delete_many({"created_by": user_id})
    await risks.delete_many({"created_by": user_id})
    await projects.update_many({"collaborators": user_id}, {"$pull": {"collaborators": user_id}})
    email = user.get("email", "")
    await sessions.delete_many({"user_id": user_id})
    await email_verifications.delete_many({"email": email})
    await otp_codes.delete_many({"email": email})
    await password_resets.delete_many({"email": email})
    await users.delete_one({"_id": user_id})

    return SuccessResponse(data={"message": "Account deleted."})


# --------------------------------------------------
# OAuth session initialization
# --------------------------------------------------

@router.get("/{provider}")
async def start_oauth(request: Request, provider: str):
    """
    Initialize an OAuth authorization flow for a supported provider.
    """

    if provider not in ["google", "facebook", "yahoo"]:
        raise HTTPException(
            status_code=404,
            detail="Unsupported OAuth provider."
        )

    client = oauth.create_client(provider)

    if not client:
        raise HTTPException(
            status_code=503,
            detail="OAuth provider is not configured."
        )

    redirect_uri = (
        f"{BACKEND_URL}/api/v1/auth/{provider}/callback"
    )

    return await client.authorize_redirect(
        request,
        redirect_uri
    )


# --------------------------------------------------
# OAuth user information
# --------------------------------------------------

async def fetch_oauth_user(provider: str, client, token: dict):
    """
    Retrieve the authenticated user's identity from the OAuth provider.
    """

    if provider == "google":
        user_info = token.get("userinfo")

        if not user_info:
            raise HTTPException(
                status_code=401,
                detail="Google did not return user information."
            )

        if not user_info.get("email_verified"):
            raise HTTPException(
                status_code=403,
                detail="Your Google email is not verified."
            )

        return {
            "provider_id": user_info["sub"],
            "email": user_info["email"],
            "username": user_info.get("name", "User")
        }

    if provider == "facebook":
        response = await client.get(
            "me",
            params={
                "fields": "id,name,email"
            },
            token=token
        )

        user_info = response.json()

        if not user_info.get("email"):
            raise HTTPException(
                status_code=400,
                detail="Facebook did not provide an email address."
            )

        return {
            "provider_id": user_info["id"],
            "email": user_info["email"],
            "username": user_info.get("name", "User")
        }

    if provider == "yahoo":
        response = await client.get(
            "openid/v1/userinfo",
            token=token
        )

        user_info = response.json()

        if not user_info.get("email"):
            raise HTTPException(
                status_code=400,
                detail="Yahoo did not provide an email address."
            )

        return {
            "provider_id": user_info["sub"],
            "email": user_info["email"],
            "username": user_info.get("name", "User")
        }

    raise HTTPException(
        status_code=400,
        detail="Unsupported OAuth provider."
    )


# --------------------------------------------------
# OAuth callback
# --------------------------------------------------

@router.get("/{provider}/callback", response_model=SuccessResponse)
async def oauth_callback(request: Request, provider: str):
    """
    Complete OAuth authentication, link or create an account,
    and issue application tokens.
    """

    if provider not in ["google", "facebook", "yahoo"]:
        raise HTTPException(
            status_code=404,
            detail="Unsupported OAuth provider."
        )

    client = oauth.create_client(provider)

    if not client:
        raise HTTPException(
            status_code=503,
            detail="OAuth provider is not configured."
        )

    try:
        token = await client.authorize_access_token(request)
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="OAuth authentication failed."
        )

    identity = await fetch_oauth_user(
        provider,
        client,
        token
    )

    provider_id = identity["provider_id"]
    email = identity["email"].lower()

    # First, look for an existing account linked to this provider.
    user = await users.find_one({
        f"oauth_identities.{provider}": provider_id
    })

    if not user:
        # Find an existing account using the same email.
        user = await users.find_one({
            "email": email
        })

        if user:
            # Link the OAuth identity to the existing account.
            await users.update_one(
                {"_id": user["_id"]},
                {
                    "$set": {
                        f"oauth_identities.{provider}": provider_id,
                        "email_verified": True,
                        "updated_at": datetime.now(timezone.utc)
                    },
                    "$addToSet": {
                        "auth_providers": provider
                    }
                }
            )

        else:
            # Create a new account for this OAuth identity.
            user_id = str(uuid4())

            user_document = {
                "_id": user_id,
                "username": identity["username"],
                "email": email,
                "password_hash": None,
                "email_verified": True,
                "phone_verified": False,
                "auth_providers": [provider],
                "oauth_identities": {
                    provider: provider_id
                },
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }

            await users.insert_one(user_document)

            user = user_document

    return SuccessResponse(data=await issue_tokens(user["_id"]))


# --------------------------------------------------
# Email verification
# --------------------------------------------------

@router.post("/verify-email", response_model=SuccessResponse)
async def verify_email(data: VerifyEmailRequest):
    """
    Validate a verification token and mark the account's email
    address as verified.
    """

    verification = await email_verifications.find_one({
        "token_hash": token_fingerprint(data.token)
    })

    if not verification:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification token."
        )

    current_time = datetime.now(timezone.utc)

    if verification["expires_at"] <= current_time:
        await email_verifications.delete_one({
            "_id": verification["_id"]
        })

        raise HTTPException(
            status_code=400,
            detail="Verification token has expired."
        )

    result = await users.update_one(
        {"email": verification["email"]},
        {
            "$set": {
                "email_verified": True,
                "updated_at": current_time
            }
        }
    )

    if result.matched_count == 0:
        raise HTTPException(
            status_code=404,
            detail="Account not found."
        )

    await email_verifications.delete_one({
        "_id": verification["_id"]
    })

    return SuccessResponse(data={"message": "Email successfully verified."})


# --------------------------------------------------
# Resend email verification
# --------------------------------------------------

@router.post("/resend-verification", response_model=SuccessResponse)
async def resend_verification(
    data: ResendVerificationRequest,
    background_tasks: BackgroundTasks
):
    """
    Generate and send a new verification token for an
    unverified account.
    """

    user = await users.find_one({
        "email": data.email
    })

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Account not found."
        )

    if user.get("email_verified", False):
        raise HTTPException(
            status_code=409,
            detail="This email address is already verified."
        )

    background_tasks.add_task(
        create_email_verification,
        data.email
    )

    return SuccessResponse(
        data={"message": "A new verification email has been sent."}
    )
