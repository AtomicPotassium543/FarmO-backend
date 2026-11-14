
from pymongo import AsyncMongoClient
import os

client = AsyncMongoClient(
    os.getenv("MONGO_URI")
)

database = client["FarmO"]

users = database["users"]
sessions = database["sessions"]
password_resets = database["password_resets"]
email_verifications = database["email_verifications"]
projects = database["projects"]
farms = database["farms"]
plants = database["plants"]
advices = database["advices"]
risks = database["risks"]