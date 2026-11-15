
import os

from dotenv import load_dotenv
from pymongo import AsyncMongoClient

# This module is imported before main.py calls load_dotenv(), so load it here
# first or MONGO_URI is still unset when the client is created.
load_dotenv()

client = AsyncMongoClient(
    os.getenv("MONGO_URI")
)

database = client["FarmO"]

users = database["users"]
sessions = database["sessions"]
password_resets = database["password_resets"]
email_verifications = database["email_verifications"]
otp_codes = database["otp_codes"]
projects = database["projects"]
farms = database["farms"]
plants = database["plants"]
advices = database["advices"]
risks = database["risks"]