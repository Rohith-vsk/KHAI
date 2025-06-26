import logging
import azure.functions as func
import os
import json
import uuid
import pymupdf as fitz  # PyMuPDF
import openai
import requests
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

# Initialize Key Vault and Managed Identity
key_vault_url = os.getenv("KEYVAULT_URL")
uami_client_id = os.getenv("UAMI_CLIENT_ID")
credential = ManagedIdentityCredential(client_id=uami_client_id)
client = SecretClient(vault_url=key_vault_url, credential=credential)

# Retrieve secrets from Key Vault
openai.api_type = "azure"
openai.api_key = client.get_secret(os.getenv("AZURE_OPENAI_KEY_NAME")).value
openai.api_base = client.get_secret(os.getenv("AZURE_OPENAI_ENDPOINT_NAME")).value
openai.api_version = client.get_secret(os.getenv("AZURE_OPENAI_VERSION_NAME")).value
deployment_id = client.get_secret(os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")).value

search_service = client.get_secret(os.getenv("AZURE_SEARCH_SERVICE_NAME")).value
search_index = client.get_secret(os.getenv("AZURE_SEARCH_INDEX_NAME")).value
search_api_key = client.get_secret(os.getenv("AZURE_SEARCH_API_KEY_NAME")).value

def extract_text_from_pdf(file_path):
    doc = fitz.open(file_path)
    text = ""
    for page in doc:
        text += page.get_text()
    doc.close()
    return text

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Function triggered to process uploaded PDF.")

    try:
        # Get uploaded file
        file = req.files.get("file")
        if not file:
            return func.HttpResponse("No file uploaded.", status_code=400)

        # Save file temporarily
        temp_file_path = f"/tmp/{uuid.uuid4()}.pdf"
        with open(temp_file_path, "wb") as f:
            f.write(file.read())

        # Extract text from PDF
        extracted_text = extract_text_from_pdf(temp_file_path)

        # Chat Completion with Azure OpenAI
        response = openai.ChatCompletion.create(
            engine=deployment_id,
            messages=[
                {"role": "system", "content": "Summarize the document."},
                {"role": "user", "content": extracted_text}
            ]
        )
        summary = response['choices'][0]['message']['content']

        # Index summary into Azure AI Search
        index_url = f"https://{search_service}.search.windows.net/indexes/{search_index}/docs/index?api-version=2020-08-01"
        headers = {
            "Content-Type": "application/json",
            "api-key": search_api_key
        }
        doc_id = str(uuid.uuid4())
        index_payload = {
            "value": [
                {
                    "@search.action": "upload",
                    "id": doc_id,
                    "title": file.filename,
                    "content": summary
                }
            ]
        }
        index_response = requests.post(index_url, headers=headers, json=index_payload)
        index_response.raise_for_status()

        # Search the index
        search_url = f"https://{search_service}.search.windows.net/indexes/{search_index}/docs/search?api-version=2020-08-01"
        search_payload = {
            "search": "architecture",
            "top": 3
        }
        search_response = requests.post(search_url, headers=headers, json=search_payload)
        search_results = search_response.json()

        return func.HttpResponse(
            json.dumps({
                "summary": summary,
                "search_results": search_results
            }, indent=2),
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(f"Internal Server Error: {str(e)}", status_code=500)
