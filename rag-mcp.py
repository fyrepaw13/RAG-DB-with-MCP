#!/usr/bin/env python3

from fastmcp import FastMCP, tool
import psycopg2
from pgvector.psycopg2 import register_vector
from sentence_transformers import SentenceTransformer

# ============================================================
# LOAD EMBEDDING MODEL (local, no internet)
# ============================================================

print("[+] Loading MiniLM embedding model...")
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

# ============================================================
# CONNECT TO POSTGRES
# ============================================================

print("[+] Connecting to PostgreSQL...")
conn = psycopg2.connect(
    "dbname=vectordb user=vectoruser password=vectorpass host=localhost port=5432"
)
register_vector(conn)
cur = conn.cursor()

# ============================================================
# FASTMCP SERVER
# ============================================================

mcp = FastMCP("RAG DB")

# ============================================================
# VECTOR SEARCH TOOL
# ============================================================

def _search_writeups(query: str, top_k: int = 3):
    """
    Internal DB search helper.
    """
    embedding = embedding_model.encode(query).tolist()

    cur.execute(
        """
        SELECT content, 1 - (embedding <=> %s) AS similarity
        FROM writeups
        ORDER BY embedding <=> %s ASC
        LIMIT %s
        """,
        (embedding, embedding, top_k),
    )

    return cur.fetchall()


@mcp.tool
def search_writeups(query: str, top_k: int = 3):
    """
    Search for similar CTF writeups.
    Returns:
        - query
        - list of {content, similarity}
    """
    rows = _search_writeups(query, top_k)

    results = [
        {"content": row[0], "similarity": float(row[1])}
        for row in rows
    ]

    return {
        "query": query,
        "results": results,
    }


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    print("[+] Starting Writeup Search MCP server on port 13339")
    mcp.run(transport="http", port="13339")
