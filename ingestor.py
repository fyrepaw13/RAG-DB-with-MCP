import psycopg2
from sentence_transformers import SentenceTransformer
import os
import glob

# Initialize the sentence transformer model
model = SentenceTransformer('all-MiniLM-L6-v2')

# Connect to the PostgreSQL database
conn = psycopg2.connect("dbname=vectordb user=vectoruser password=vectorpass host=localhost")
cur = conn.cursor()

# Configuration
writeups_dir = "./writeups"
chunk_size = 1000  # characters per chunk
overlap = 200      # overlap between chunks

def chunk_text(text, chunk_size=1000, overlap=200):
    """Split text into overlapping chunks."""
    chunks = []
    start = 0
    text_len = len(text)
    
    while start < text_len:
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk)
        start += chunk_size - overlap
    
    return chunks

# Get all markdown files from the writeups directory
markdown_files = glob.glob(os.path.join(writeups_dir, "*.md"))

if not markdown_files:
    print(f"No markdown files found in {writeups_dir}")
    exit(1)

print(f"Found {len(markdown_files)} markdown file(s) to process")
print(f"Chunk size: {chunk_size} chars, Overlap: {overlap} chars\n")

total_chunks = 0
skipped_files = 0

# Process each markdown file
for md_file in markdown_files:
    print(f"Processing: {md_file}")
    
    try:
        # Read the content of the markdown file
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        filename = os.path.basename(md_file)
        
        # Check if this writeup already exists by checking for content with the filename prefix
        cur.execute("SELECT id FROM writeups WHERE content LIKE %s LIMIT 1", (f"[{filename}]%",))
        existing = cur.fetchone()
        
        if existing:
            print(f"⊘ Skipped: {filename} (already exists)")
            skipped_files += 1
            continue
        
        # Split into chunks if content is large
        if len(content) > chunk_size:
            chunks = chunk_text(content, chunk_size, overlap)
            print(f"  Split into {len(chunks)} chunks")
            
            for i, chunk in enumerate(chunks):
                # Prepend filename to each chunk for context
                chunk_with_context = f"[{filename}]\n{chunk}"
                
                # Generate embedding for the chunk
                embedding = model.encode(chunk_with_context)
                
                # Insert the chunk and its embedding
                cur.execute(
                    "INSERT INTO writeups (content, embedding) VALUES (%s, %s)",
                    (chunk_with_context, embedding.tolist())
                )
                total_chunks += 1
        else:
            # For small documents, insert as-is
            content_with_context = f"[{filename}]\n{content}"
            embedding = model.encode(content_with_context)
            
            cur.execute(
                "INSERT INTO writeups (content, embedding) VALUES (%s, %s)",
                (content_with_context, embedding.tolist())
            )
            total_chunks += 1
            print(f"  Inserted as single document")
        
        print(f"✓ Completed: {filename}")
        
    except Exception as e:
        print(f"✗ Error processing {md_file}: {e}")
        continue

# Commit all changes
conn.commit()

# Display summary
cur.execute("SELECT COUNT(*) FROM writeups")
db_count = cur.fetchone()[0]
print(f"\n{'='*50}")
print(f"Processing complete!")
print(f"Files found: {len(markdown_files)}")
print(f"Files processed: {len(markdown_files) - skipped_files}")
print(f"Files skipped (duplicates): {skipped_files}")
print(f"Total chunks inserted: {total_chunks}")
print(f"Total entries in database: {db_count}")
print(f"{'='*50}")

# Close database connection
cur.close()
conn.close()