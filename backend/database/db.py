import sys
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from config import Config

_client = None
_db = None
_db_source = "DISCONNECTED"

def init_db():
    """Initializes MongoDB connection and creates required security indexes."""
    global _client, _db, _db_source

    if _db is not None:
        return _db

    mongo_uri = Config.MONGO_URI.strip()
    db_name = Config.MONGO_DB_NAME

    # 1. Attempt Atlas URI if configured
    if mongo_uri:
        try:
            client = MongoClient(
                mongo_uri,
                serverSelectionTimeoutMS=4000,
                connectTimeoutMS=4000,
                appname="AegisAuth-ZTA"
            )
            client.admin.command("ping")
            _client = client
            _db = _client[db_name]
            _db_source = "atlas"
            print(f"[+] Connected to MongoDB Atlas cluster for AegisAuth ({db_name}).")
            _setup_indexes(_db)
            return _db
        except Exception as e:
            print(f"[!] MongoDB Atlas connection failed ({e}). Falling back to local MongoDB service...")

    # 2. Connect to Local MongoDB Service (127.0.0.1:27017)
    try:
        client = MongoClient(
            "mongodb://127.0.0.1:27017",
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000
        )
        client.admin.command("ping")
        _client = client
        _db = _client[db_name]
        _db_source = "local"
        print(f"[+] Connected to Local MongoDB Server at 127.0.0.1:27017, database '{db_name}'.")
        _setup_indexes(_db)
        return _db
    except (ConnectionFailure, ServerSelectionTimeoutError) as err:
        _client = None
        _db = None
        _db_source = "DISCONNECTED"
        print(f"[X] CRITICAL: Could not connect to MongoDB service: {err}", file=sys.stderr)
        return None

def _setup_indexes(db):
    """Sets up indexes on users, access logs, and active sessions for fast Zero Trust queries."""
    try:
        # Users: unique index on lowercase email
        db["users"].create_index([("email", ASCENDING)], unique=True)
        # Access logs: index on timestamp desc and user_id
        db["access_logs"].create_index([("timestamp", DESCENDING)])
        db["access_logs"].create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)])
        # Active sessions: index on session_id and user_id
        db["active_sessions"].drop_indexes()
        db["active_sessions"].create_index([("session_id", ASCENDING)], unique=True)
        db["active_sessions"].create_index([("user_id", ASCENDING)])
        # Rate limits: index on key and timestamp
        db["rate_limits"].create_index([("key", ASCENDING), ("timestamp", DESCENDING)])
    except Exception as e:
        print(f"[!] Warning while creating database indexes: {e}")

def get_db():
    if _db is None:
        return init_db()
    return _db

def get_db_source():
    return _db_source

def get_db_status():
    return {
        "connected": _db is not None,
        "source": _db_source,
        "database": Config.MONGO_DB_NAME if _db is not None else None
    }

def get_users_collection():
    db = get_db()
    return db["users"] if db is not None else None

def get_logs_collection():
    db = get_db()
    return db["access_logs"] if db is not None else None

def get_sessions_collection():
    db = get_db()
    return db["active_sessions"] if db is not None else None

def get_rate_limits_collection():
    db = get_db()
    return db["rate_limits"] if db is not None else None

