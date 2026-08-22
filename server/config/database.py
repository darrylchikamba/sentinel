import os
import sys

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    print()
    print("ERROR: MONGO_URI environment variable is missing.")
    print("Create server/.env from .env.example and provide MONGO_URI.")
    print()
    sys.exit(1)

_client = None
_database = None


def get_database():
    """
    Lazily creates the MongoDB client.

    This does NOT verify connectivity at application startup.
    The connection is established only when the database is first used.
    """
    global _client
    global _database

    if _database is None:
        _client = MongoClient(MONGO_URI)
        _database = _client["sentinel"]

    return _database