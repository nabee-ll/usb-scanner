import os
import sqlite3

DB_NAME = os.path.join(os.path.dirname(__file__), "test_malware.db")

# EICAR test file — standard antivirus test string, not real malware.
SAMPLE_HASHES = [
    (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR-Test-File",
        "test",
    ),
]


def ensure_database(db_path=None):
    """Create the malware hash database if it does not exist."""
    db_path = db_path or DB_NAME
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS malware_hashes (
            sha256_hash TEXT PRIMARY KEY,
            signature TEXT NOT NULL,
            severity TEXT NOT NULL
        )
    """)
    for sha256_hash, signature, severity in SAMPLE_HASHES:
        conn.execute(
            "INSERT OR REPLACE INTO malware_hashes (sha256_hash, signature, severity) VALUES (?, ?, ?)",
            (sha256_hash, signature, severity),
        )
    conn.commit()
    conn.close()
    return db_path


if __name__ == "__main__":
    path = ensure_database()
    print(f"[+] Database ready: {path}")
