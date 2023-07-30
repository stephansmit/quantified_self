import requests
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

KEY_VAULT_NAME = 'quant-self-kv'
SECRET_NAME_MOODPANDA_PASSWORD = 'moodpanda-password'
SECRET_NAME_MOODPANDA_USERNAME = 'moodpanda-username'
STORAGE_ACCOUNT_NAME = 'quantselfdevsa'

# get the secrets from key vault
credential = DefaultAzureCredential()
client = SecretClient(vault_url=f"https://{KEY_VAULT_NAME}.vault.azure.net/", credential=credential)
moodpanda_password = client.get_secret(SECRET_NAME_MOODPANDA_PASSWORD).value
moodpanda_username = client.get_secret(SECRET_NAME_MOODPANDA_USERNAME).value

# get the jwt token
auth_data = {"username": moodpanda_username, 
             "password": moodpanda_password} 
headers = {"Content-Type": "application/json"}
AUTH_URL = "https://moodpanda.com/api/users/authenticate"
auth_resp = requests.post(url=AUTH_URL,
                          json=auth_data,
                          headers=headers,
                          timeout=5)
jwt_token = auth_resp.json()["jwtToken"]

# get the ratings
RATING_URL = "https://moodpanda.com/api/ratings/me"

header_w_jwt = {"Authorization": f"Bearer {jwt_token}",
                "Content-Type": "application/json"}

rating_resp = requests.get(RATING_URL,
                           headers=header_w_jwt,
                           timeout=5)

