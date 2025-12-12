#!/usr/bin/env python3

from pathlib import Path
import psycopg2
from pgvector.psycopg2 import register_vector
from openai import OpenAI
from dotenv import load_dotenv
import os

# ---------------- LOAD ENV ----------------
load_dotenv()  # Loads .env file
OPENAI_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_KEY:
    raise RuntimeError("ERROR: OPENAI_API_KEY is not set in .env")
# ------------------------------------------

# ---------------- CONFIG ----------------
OPENAI_MODEL = "text-embedding-3-small"
WRITEUPS_DIR = Path("writeups")
DSN = "dbname=vectordb user=vectoruser password=vectorpass host=localhost port=5432"
# -----------------------------------------

def load_markdown_files(folder: Path):
    """Return all .md files in the folder."""
    return sorted([f for f in folder.glob("*.md") if f.is_file()])


def read_file(path: Path) -> str:
    """Read file text as UTF-8 text."""
    return path.read_text(encoding="utf-8").strip()


def main():
    # Load markdown files
    files = load_markdown_files(WRITEUPS_DIR)
    if not files:
        print("[!] No markdown files found in writeups/")
        return

    print(f"[+] Found {len(files)} writeups")

    # Connect to OpenAI
    client = OpenAI(api_key=OPENAI_KEY)

    # Connect to PostgreSQL
    conn = psycopg2.connect(DSN)
    register_vector(conn)
    cur = conn.cursor()

    for md_file in files:
        print(f"\n[+] Processing: {md_file.name}")

        content = read_file(md_file)
        if not content:
            print(f"[WARN] Skipping empty file: {md_file}")
            continue

        # ------ Generate embedding --------
        print("[+] Generating OpenAI embedding...")
        embedding_response = client.embeddings.create(
            model=OPENAI_MODEL,
            input=content
        )
        embedding = embedding_response.data[0].embedding
        print(f"[+] Embedding dimension: {len(embedding)}")
        # -----------------------------------

        # Insert into DB
        cur.execute(
            "INSERT INTO writeups (content, embedding) VALUES (%s, %s)",
            (content, embedding)
        )
        conn.commit()

        print(f"[✓] Inserted {md_file.name} into database")

    cur.close()
    conn.close()
    print("\n[+] Done — all writeups ingested successfully.")


if __name__ == "__main__":
    main()
