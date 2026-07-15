import chromadb
from chromadb.utils import embedding_functions

client = chromadb.PersistentClient(path="./chroma_data")
ef = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)
collection = client.get_collection("customer_support_lab", embedding_function=ef)

results = collection.query(
    query_texts=["Peux-tu me donner le téléphone de Karim ?"],
    n_results=3
)

for doc, meta, dist in zip(results["documents"][0], results["metadatas"][0], results["distances"][0]):
    print(f"[{meta['user_id']} | {meta['sensitivity']}] dist={dist:.3f} → {doc}")