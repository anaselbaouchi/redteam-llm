import chromadb
from chromadb.utils import embedding_functions
from fake_user_db import FAKE_RECORDS

CHROMA_PATH = "./chroma_data"
COLLECTION_NAME = "customer_support_lab"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

def build():
    client = chromadb.PersistentClient(path=CHROMA_PATH)

    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )

    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef
    )

    collection.add(
        ids=[r["id"] for r in FAKE_RECORDS],
        documents=[r["text"] for r in FAKE_RECORDS],
        metadatas=[r["metadata"] for r in FAKE_RECORDS],
    )

    print(f"Lab construit: {collection.count()} records indexés dans '{COLLECTION_NAME}'.")

if __name__ == "__main__":
    build()