import logging
import azure.functions as func
import json
import os
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
import openai
import requests #for Azure Search

# Load Environment Variables
key_vault_url = os.getenv("KEYVAULT_URL")
uami_client_id = os.getenv("UAMI_CLIENT_ID")

# Initialize credential and Key Vault client
credential = ManagedIdentityCredential(client_id=uami_client_id)
client = SecretClient(vault_url=key_vault_url, credential=credential)

# Retrieve secrets from KeyVault using secret names stored in Environment Variables
openai.api_type = "azure"
openai.api_key = client.get_secret(os.getenv("AZURE_OPENAI_KEY_NAME")).value
openai.api_base = client.get_secret(os.getenv("AZURE_OPENAI_ENDPOINT_NAME")).value
openai.api_version = client.get_secret(os.getenv("AZURE_OPENAI_VERSION_NAME")).value
deployment_id = client.get_secret(os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")).value


# Azure Search config
search_service = client.get_secret(os.getenv("AZURE_SEARCH_SERVICE_NAME")).value
search_index = client.get_secret(os.getenv("AZURE_SEARCH_INDEX_NAME")).value
search_api_key = client.get_secret(os.getenv("AZURE_SEARCH_API_KEY_NAME")).value


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing chat completion request.")

    try:
        req_body = req.get_json()
        query = req_body.get("query")
        search_query = req_body.get("searchQuery")
        use_search = req_body.get("use_search", False)

        if not query:
            return func.HttpResponse("Missing 'query' in request body.", status_code=400)
        
        search_results = None
        if use_search:
            search_results = query_azure_search(search_query, search_service, search_index, search_api_key)

        response = openai.ChatCompletion.create(
            engine=deployment_id,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": query}
            ]
        )

        reply = response['choices'][0]['message']['content']
        return func.HttpResponse(json.dumps({"response": reply,"search_results": search_results}), mimetype="application/json")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(f"Internal Server Error: {str(e)}", status_code=500)


#Query Azure AI Search


def query_azure_search(query_text: str, search_service: str, index_name: str, api_key: str):
    url = f"https://{search_service}.search.windows.net/indexes/{index_name}/docs/search?api-version=2020-08-01"
    headers = {
        "Content-Type": "application/json",
        "api-key": api_key
    }
    payload = {
        "search": query_text,
        "top": 5
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()
