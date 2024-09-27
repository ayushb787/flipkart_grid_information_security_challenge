"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import src.owasp_tests.log as logs
import os

try:
    import requests

    requests.packages.urllib3.disable_warnings()
except:
    print("[-]Failed to import requests module")


def update_header_w_auth(headers):
    new_auth = os.environ['auth_header']
    headers.update({'Authorization': new_auth})


# def api_request(url, method, headers, body=None):
#     try:
#         headers = update_header_w_auth(headers)
#     except:
#         # print("Authorization header not specified")
#         pass
#     try:
#         if method.upper() == "GET":
#             auth_request = requests.get(url, headers=headers, allow_redirects=False, verify=False, timeout=10)
#             return auth_request
#         elif method.upper() == "POST":
#             auth_request = requests.post(url, headers=headers, data=body, allow_redirects=False, verify=False,
#                                          timeout=10)
#             return auth_request
#         elif method.upper() == "PUT":
#             auth_request = requests.put(url, headers=headers, data=body, allow_redirects=False, verify=False,
#                                         timeout=10)
#             return auth_request
#         elif method.upper() == "OPTIONS":
#             auth_request = requests.options(url, headers=headers, verify=False, timeout=10)
#             return auth_request
#
#     except Exception as e:
#         logs.logging.error("Exception from sendrequest %s", e)

def api_request(url, method, headers, body=None):
    try:
        headers = update_header_w_auth(headers)
    except Exception as e:
        logs.logging.error("Authorization header not specified: %s", e)
        return None

    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, allow_redirects=True, verify=False, timeout=10)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, data=body, allow_redirects=False, verify=False, timeout=10)
        elif method.upper() == "PUT":
            response = requests.put(url, headers=headers, data=body, allow_redirects=False, verify=False, timeout=10)
        elif method.upper() == "OPTIONS":
            response = requests.options(url, headers=headers, verify=False, timeout=10)
        else:
            logs.logging.error("Unsupported method: %s", method)
            return None

        logs.logging.info("Request to %s with method %s returned status code %d", url, method, response.status_code)
        return response
    except requests.RequestException as e:
        logs.logging.error("Request exception in api_request: %s", e)
        return None
    except Exception as e:
        logs.logging.error("General exception in api_request: %s", e)
        return None
