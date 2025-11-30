# threat_intel_rag.py
#----------------------
# This script sets up a Retrieval-Augmented Generation (RAG) pipeline for Cyber Threat Intelligence
# using LangChain, ChromaDB, and HuggingFace embeddings. It loads documents from a text file,
# processes them, and allows querying via an LLM (OpenAI's GPT-3.5-turbo).
#----------------------

from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema.document import Document
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.output_parser import StrOutputParser

from dotenv import load_dotenv
load_dotenv()

print("--- Initializing RAG Pipeline for Cyber Threat Intelligence ---")

# ---
# **STEP 1: LOAD KNOWLEDGE BASE FROM .TXT FILE (DATA PREP)**
# This is the updated section. We now load from a text file.
# ---
print("\n[STEP 1] Loading knowledge base from knowledge_base.txt...")

# Load the raw text from the file
loader = TextLoader("./knowledge_base.txt")
raw_text_data = loader.load()

# The file is loaded as a single document. We need to split it into chunks
# based on our '---' separator.
text_content = raw_text_data[0].page_content
all_splits = text_content.split('---')

# Clean up any leading/trailing whitespace from the splits
document_strings = [split.strip() for split in all_splits if split.strip()]

# For this demo, we'll manually associate the metadata.
# In a production system, this metadata might come from the filename,
# a separate file (like JSON or CSV), or be embedded in the document itself.
metadata_list = [
    {"source": "Internal Incident Report", "doc_id": "IR-2025-001", "timestamp": "2025-10-15T10:00:00Z"},
    {"source": "CISA KEV Catalog", "doc_id": "CISA-2025-034", "timestamp": "2025-10-12T14:30:00Z"},
    {"source": "External TI Feed", "doc_id": "TIR-567", "timestamp": "2025-10-15T09:00:00Z"},
    {"source": "Internal SOC Runbook", "doc_id": "RB-042", "timestamp": "2024-01-20T18:00:00Z"}
]

# Create LangChain Document objects, combining content with metadata
documents = []
for i, doc_str in enumerate(document_strings):
    if i < len(metadata_list):
        documents.append(Document(page_content=doc_str, metadata=metadata_list[i]))

print(f"Loaded and parsed {len(documents)} documents from the file.")

# Print two sample documents to verify
for i, doc in enumerate(documents[:2]):
    print(f"\nSample Document {i+1}:")
    print(f"Metadata: {doc.metadata}")
    print(f"Content Preview: {doc.page_content[:200]}...")  # Print first 200 chars

# ---
# **STEP 2: CHUNKING (No change, as our docs are already chunk-sized)**
# ---
chunked_documents = documents
print(f"\n[STEP 2] Documents are prepared for vectorization.")


# ---
# **STEP 3: VECTORIZATION AND STORAGE (ChromaDB + HuggingFace)**
# ---
print("\n[STEP 3] Initializing OpenAI embedding model and vector store...")
# Use OpenAI embeddings (requires OPENAI_API_KEY in the environment)
embedding_model = OpenAIEmbeddings()
vectorstore = Chroma.from_documents(
    documents=chunked_documents,
    embedding=embedding_model,
    persist_directory="./chroma_db_cyber"
)
print("Vector store created and documents ingested successfully.")


# ---
# **STEP 4: CREATE THE RETRIEVER**
# ---
print("\n[STEP 4] Configuring the retriever...")
retriever = vectorstore.as_retriever(
    search_type="similarity",
    search_kwargs={'k': 3}
)
print("Retriever configured to fetch top 3 results.")


# ---
# **STEP 5: DEFINE LLM AND PROMPT TEMPLATE**
# ---
print("\n[STEP 5] Defining the LLM and Prompt Template...")
llm = ChatOpenAI(model_name="gpt-4o", temperature=0)
template = """
You are a senior cyber security analyst assistant. Your task is to provide clear, concise answers to questions based *only* on the provided context.
Do not use any external knowledge. If the context does not contain the answer, state that the information is not available in the provided documents.

Context:
{context}

Question:
{question}

Answer:
"""
prompt = ChatPromptTemplate.from_template(template)


# ---
# **STEP 6: BUILD THE RAG CHAIN**
# ---
print("\n[STEP 6] Assembling the RAG chain...")
rag_chain = (
    {"context": retriever, "question": RunnablePassthrough()}  
    | prompt
    | llm
    | StrOutputParser()
)
print("RAG chain assembled successfully.")


# ---
# **STEP 7: EXECUTE AND DEMONSTRATE**
# ---
print("\n--- Starting RAG Chain Demonstration ---")

# **Query 1: Specific IOC lookup**
query1 = "What do we know about the IP address 185.199.110.153?"
print(f"\n[DEMO 1] Asking query: \"{query1}\"")
answer1 = rag_chain.invoke(query1)
print("\n**Generated Answer:**")
print(answer1)

# **Query 2: Semantic TTP lookup**
query2 = "What is the procedure for handling lateral movement?"
print(f"\n[DEMO 2] Asking query: \"{query2}\"")
answer2 = rag_chain.invoke(query2)
print("\n**Generated Answer:**")
print(answer2)

# **Query 3: Question with no context (testing for hallucination)**
query3 = "What is the capital of Australia?"
print(f"\n[DEMO 3] Asking query: \"{query3}\"")
answer3 = rag_chain.invoke(query3)
print("\n**Generated Answer:**")
print(answer3)

print("\n--- RAG Chain Demonstration Complete ---")