#!/usr/bin/env python3
"""
Sample 2: RAG Document Q&A (SDK Mode)

This simulates a RAG (Retrieval Augmented Generation) application where
sensitive internal documents are retrieved and used as context.
AIRS-CP tracks data taint/lineage to prevent sensitive data leakage.

USAGE:
    # Start AIRS-CP gateway first
    uvicorn airs_cp.gateway.app:app --port 8080
    
    # Then run this app
    python samples/02_rag_sdk.py

WHAT IT TESTS:
    - SDK integration with session tracking
    - Taint tracking (data lineage)
    - Sensitivity propagation from RAG documents
    - Prevention of sensitive data flowing to wrong sinks
"""

import os
import sys
import json

# Add src to path for SDK
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from openai import OpenAI
except ImportError:
    print("ERROR: Please install openai: pip install openai")
    sys.exit(1)

from airs_cp.security.taint import TaintEngine
from airs_cp.store.models import TaintSourceType, TaintSensitivity


# Simulated document database (in real app, this would be ChromaDB, Pinecone, etc.)
DOCUMENT_DATABASE = {
    "doc_001": {
        "title": "Employee Handbook",
        "content": "All employees must follow the code of conduct. Vacation policy is 20 days per year.",
        "sensitivity": "internal",
    },
    "doc_002": {
        "title": "Customer Data Policy",
        "content": "Customer PII must never be shared externally. Data retention is 7 years.",
        "sensitivity": "confidential",
    },
    "doc_003": {
        "title": "Executive Compensation",
        "content": "CEO salary: $2.5M. CFO salary: $1.8M. Stock options vest over 4 years.",
        "sensitivity": "restricted",
    },
    "doc_004": {
        "title": "Public FAQ",
        "content": "Our company was founded in 2010. We have offices in 15 countries.",
        "sensitivity": "public",
    },
}


def simulate_rag_retrieval(query: str) -> list:
    """Simulate RAG document retrieval (in real app, would be vector similarity search)."""
    # Simple keyword matching for demo
    results = []
    query_lower = query.lower()
    
    for doc_id, doc in DOCUMENT_DATABASE.items():
        if any(word in doc["content"].lower() or word in doc["title"].lower() 
               for word in query_lower.split()):
            results.append({"id": doc_id, **doc})
    
    # If no matches, return public doc
    if not results:
        results.append({"id": "doc_004", **DOCUMENT_DATABASE["doc_004"]})
    
    return results[:2]  # Return top 2


def sensitivity_to_enum(sensitivity: str) -> TaintSensitivity:
    """Convert string sensitivity to enum."""
    mapping = {
        "public": TaintSensitivity.PUBLIC,
        "internal": TaintSensitivity.INTERNAL,
        "confidential": TaintSensitivity.CONFIDENTIAL,
        "restricted": TaintSensitivity.RESTRICTED,
    }
    return mapping.get(sensitivity, TaintSensitivity.PUBLIC)


class SecureRAGApplication:
    """RAG application with AIRS-CP taint tracking."""
    
    def __init__(self, gateway_url: str = "http://localhost:8080"):
        self.client = OpenAI(
            base_url=f"{gateway_url}/v1",
            api_key=os.getenv("OPENAI_API_KEY", "not-needed-for-ollama"),
        )
        self.taint_engine = TaintEngine()
        self.model = os.getenv("AIRS_MODEL", "llama3.2:1b")
    
    def query(self, user_question: str, user_id: str = "user_123") -> dict:
        """Process a RAG query with taint tracking."""
        
        # Step 1: Create taint for user input
        user_taint = self.taint_engine.create_taint(
            content=user_question,
            source_type=TaintSourceType.USER_INPUT,
            source_id=user_id,
            sensitivity=TaintSensitivity.PUBLIC,  # User input starts public
            label="user_query",
        )
        
        # Step 2: Retrieve documents
        retrieved_docs = simulate_rag_retrieval(user_question)
        
        # Step 3: Create taints for each retrieved document
        doc_taints = []
        for doc in retrieved_docs:
            doc_taint = self.taint_engine.create_taint(
                content=doc["content"],
                source_type=TaintSourceType.RAG_DOC,
                source_id=doc["id"],
                sensitivity=sensitivity_to_enum(doc["sensitivity"]),
                label=f"doc:{doc['id']}",
            )
            doc_taints.append(doc_taint)
        
        # Step 4: Build context from retrieved docs
        context = "\n\n".join([
            f"[{doc['title']}]: {doc['content']}" 
            for doc in retrieved_docs
        ])
        
        # Step 5: Create prompt with context
        messages = [
            {
                "role": "system",
                "content": f"You are a helpful assistant. Use the following context to answer questions.\n\nContext:\n{context}"
            },
            {
                "role": "user",
                "content": user_question
            }
        ]
        
        # Step 6: Call LLM through AIRS-CP
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
            )
            llm_response = response.choices[0].message.content
        except Exception as e:
            llm_response = f"Error calling LLM: {e}"
        
        # Step 7: Create taint for model output (inherits from inputs)
        # Use the highest sensitivity document's taint
        if doc_taints:
            highest_sensitivity_taint = max(
                doc_taints, 
                key=lambda t: list(TaintSensitivity).index(t.max_sensitivity)
            )
        else:
            highest_sensitivity_taint = None
        
        output_taint = self.taint_engine.model_output(
            prompt=user_taint,
            system_prompt=None,
            context=highest_sensitivity_taint,
            output_content=llm_response,
            model_name=self.model,
        )
        
        # Step 8: Check if response can go to different sinks
        response_sink = self.taint_engine.check_sink(output_taint, "response")
        api_sink = self.taint_engine.check_sink(output_taint, "external_api")
        log_sink = self.taint_engine.check_sink(output_taint, "audit_log")
        
        return {
            "question": user_question,
            "retrieved_docs": [{"id": d["id"], "title": d["title"], "sensitivity": d["sensitivity"]} 
                             for d in retrieved_docs],
            "response": llm_response,
            "taint_info": {
                "output_sensitivity": output_taint.max_sensitivity.value,
                "inherited_labels": list(output_taint.labels),
                "can_send_to_user": response_sink["allowed"],
                "can_send_to_external_api": api_sink["allowed"],
                "can_log": log_sink["allowed"],
                "alerts": response_sink.get("alerts", []) + api_sink.get("alerts", []),
            }
        }


def main():
    print("=" * 60)
    print("  RAG Document Q&A (SDK Mode)")
    print("  Testing AIRS-CP Taint Tracking")
    print("=" * 60)
    
    app = SecureRAGApplication()
    
    # Test scenarios
    test_queries = [
        # Query that retrieves public doc only
        {
            "query": "When was the company founded?",
            "expected_sensitivity": "public",
            "expected_external_api": True,
        },
        # Query that retrieves internal doc
        {
            "query": "What is the vacation policy?",
            "expected_sensitivity": "internal",
            "expected_external_api": True,
        },
        # Query that retrieves confidential doc
        {
            "query": "What is the data retention policy for customers?",
            "expected_sensitivity": "confidential",
            "expected_external_api": False,
        },
        # Query that retrieves restricted doc (executive salaries)
        {
            "query": "What is the CEO salary?",
            "expected_sensitivity": "restricted",
            "expected_external_api": False,
        },
        # Query with PII (tests gateway PII detection)
        {
            "query": "My SSN is 123-45-6789, can you look up my employee record?",
            "expected_sensitivity": "public",  # Query itself doesn't determine doc sensitivity
            "expected_external_api": True,
            "has_pii": True,
        },
        # Query with email (tests gateway PII detection)
        {
            "query": "Please send the policy to john.doe@company.com",
            "expected_sensitivity": "public",
            "expected_external_api": True,
            "has_pii": True,
        },
    ]
    
    for i, test in enumerate(test_queries, 1):
        print(f"\n--- Test {i}: {test['query'][:50]}... ---")
        print(f"Expected sensitivity: {test['expected_sensitivity']}")
        print(f"Expected can send to external API: {test['expected_external_api']}")
        print()
        
        result = app.query(test["query"])
        
        print(f"Retrieved docs: {[d['title'] for d in result['retrieved_docs']]}")
        print(f"Response: {result['response'][:150]}...")
        print()
        print("Taint Analysis:")
        print(f"  Output sensitivity: {result['taint_info']['output_sensitivity']}")
        print(f"  Inherited labels: {result['taint_info']['inherited_labels']}")
        print(f"  Can send to user: {result['taint_info']['can_send_to_user']}")
        print(f"  Can send to external API: {result['taint_info']['can_send_to_external_api']}")
        
        if result['taint_info']['alerts']:
            print("  ⚠️ Alerts:")
            for alert in result['taint_info']['alerts']:
                print(f"    - {alert.get('message', alert)}")
        
        # Verify expectations
        actual_sensitivity = result['taint_info']['output_sensitivity']
        if actual_sensitivity == test['expected_sensitivity']:
            print("  ✓ Sensitivity matches expected")
        else:
            print(f"  ✗ Sensitivity mismatch: got {actual_sensitivity}")
        
        print("-" * 40)
    
    print("\n" + "=" * 60)
    print("  RAG Tests Complete!")
    print("  Taint tracking prevents sensitive data leakage")
    print("=" * 60)


if __name__ == "__main__":
    main()
