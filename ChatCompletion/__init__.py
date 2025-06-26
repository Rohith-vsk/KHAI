import logging
import azure.functions as func
import json
import os
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
import openai

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

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing chat completion request.")

    try:
        req_body = req.get_json()
        query = req_body.get("query")

        if not query:
            return func.HttpResponse("Missing 'query' in request body.", status_code=400)

        response = openai.ChatCompletion.create(
            engine=deployment_id,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": query}
            ]
        )

        reply = response['choices'][0]['message']['content']
        return func.HttpResponse(json.dumps({"response": reply}), mimetype="application/json")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(f"Internal Server Error: {str(e)}", status_code=500)
