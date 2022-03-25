import token
from apt import Version
import requests
import json

import urllib3
def get_api_token(url):
    response = requests.post(url, verify=False, data={"grant_type": "client_credentials"},
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             params={"client_id": API_TOKEN_CLIENT_ID, "client_secret": API_TOKEN_CLIENT_PASS})
 
    if response is not None:
        return json.loads(response.text)["access_token"]
 
    return None
API_GET_ADVISORIES = "https://api.cisco.com/security/advisories/ios/?version={0}"
 
def get_advisories_by_release(token, ver):   requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(API_GET_ADVISORIES.format(Version), verify=False,
                            headers={"Authorization": "Bearer {0}".format(token), "Accept": "application/json"})
 
    if response.status_code == 200:
        return json.loads(response.text)
 
    return None

def main():
    version = "12.2(55)SE10"
    res = get_advisories_by_release(get_api_token(), version)
 
    print("Release {0} has {1} advisories".format(version, len(res))
