⚡ This project is based on / modified from: https://gist.github.com/Joel-hanson/132138e0a6720013dca669546fe98777

## Step 1: Building a Custom PostgreSQL Image with pgvector

1. Go to the directory of your Dockerfile

```bash
cd postgres-pgvector
```

2. Build the Docker image:

```bash
docker build -t postgres-pgvector .
```

3. Run the container:

```bash
docker run -d --name postgres-vector -p 5432:5432 postgres-pgvector
```

You now have a PostgreSQL instance running with pgvector ready to go.

## Step 2: Install Required Python Packages

Let's set up our Python environment:

```bash
pip install psycopg2-binary pgvector sentence-transformers torch transformers
```

## Step 3: Create a Table for Vector Storage

1. Connect to your PostgreSQL database 

```bash
docker exec -it postgres-vector psql -U vectoruser -d vectordb
```

2. Run

```sql
CREATE TABLE writeups (
    id SERIAL PRIMARY KEY,
    content TEXT,
    embedding vector(384)
);
```

If you are using OpenAI's text-embedding-3-small, you should create vector(1536)

## Step 4: Ingest your Writeups

Run `python3 ingestor.py` to add it into the db
