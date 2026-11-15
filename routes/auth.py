
import os
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt

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
from database import users, sessions, email_verifications

# Existing JWT helpers
from utils.auth import password_hash, create_token_pair, decode_token, token_fingerprint
from utils.responses import ErrorResponse, SuccessResponse

password_hasher = PasswordHash.recommended()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

FRONTEND_URL = os.getenv("FRONTEND_URL")
BACKEND_URL = os.getenv("BACKEND_URL")

VERIFICATION_EXPIRY = timedelta(minutes=30)

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
# Registration
# --------------------------------------------------

@router.post("/register", response_model=SuccessResponse)
async def register(
    data: RegisterRequest,
    background_tasks: BackgroundTasks
):
    """
    Register a new account and initiate email verification.
    """

    existing_user = await users.find_one({
        "email": data.email
    })

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists."
        )

    user_id = str(uuid4())
    username = data.username or (data.name and data.name.lower().replace(" ", "_")) or data.email.split("@")[0]
    is_dev = os.getenv("APP_ENV", "development").lower() == "development" or not os.getenv("SMTP_USERNAME")

    user_document = {
        "_id": user_id,
        "username": username,
        "name": data.name or username,
        "phone": data.phone or "",
        "email": data.email,
        "password_hash": password_hasher.hash(data.password),
        "email_verified": True if is_dev else False,
        "auth_providers": ["password"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }

    await users.insert_one(user_document)

    if not is_dev:
        background_tasks.add_task(
            create_email_verification,
            data.email
        )

    token_data = await issue_tokens(user_id)
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

    if not user.get("email_verified", False):
        if os.getenv("APP_ENV", "development").lower() == "development" or not os.getenv("SMTP_USERNAME"):
            await users.update_one({"_id": user["_id"]}, {"$set": {"email_verified": True}})
            user["email_verified"] = True
        else:
            raise HTTPException(
                status_code=403,
                detail="Please verify your email before logging in."
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
        updates["phone"] = data.phone.strip()
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
