from config.settings import AppSettings
from backend.database.connection import SQLiteConnectionFactory
from backend.database.malware_repository import MalwareHashRepository


def ensure_database(db_path=None):
    """Create and seed the malware hash database if it does not exist."""
    database_path = db_path or AppSettings().database_path
    repository = MalwareHashRepository(SQLiteConnectionFactory(database_path))
    repository.seed()
    return database_path


if __name__ == "__main__":
    path = ensure_database()
    print(f"[+] Database ready: {path}")
