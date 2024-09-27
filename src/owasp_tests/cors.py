"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import requests
import json
from loguru import logger
import src.owasp_tests.log as logs
from urllib.parse import urlparse



def cors_check(origin, res_headers):
    # This function checks if the API is vulnerable to Cross-Origin Resource Sharing attack.
    result = {}
    if all(k in res_headers for k in ("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials")):
        allow_origin_header = res_headers['Access-Control-Allow-Origin']
        if origin.lower() == allow_origin_header.lower() or origin.lower() == allow_origin_header[
                                                                              allow_origin_header.find(
                                                                                      '://') + 3:].lower():
            if res_headers['Access-Control-Allow-Credentials'] == 'true':
                result.update({"impact": "High"})
            else:
                result.update({"impact": "Low"})
        elif allow_origin_header == '*':
            result.update({"impact": "Low"})
    elif 'Access-Control-Allow-Origin' in res_headers:
        result.update({"impact": "Low"})
    return result


def check_custom_header(url, header_name):
    # Check if custom header is allowed to send.
    request_header = {'Access-Control-Request-Headers': header_name}
    try:
        req_custom_header = requests.options(url, headers=request_header, verify=False)
        return req_custom_header.headers.get('Access-Control-Allow-Headers') == header_name
    except:
        return False


def generate_origin(url):
    # Generate different possible origin URLs.
    origin_headers = []
    protocol = url[:url.find(':')]
    origin = 'http://attackersite.com'
    if protocol == 'https':
        origin = 'https://attackersite.com'

    domain_name = urlparse(url).hostname
    postfix_url = f'{domain_name}.attackersite.com'
    origin_headers.append(origin)
    origin_headers.append(postfix_url)
    logs.logging.info("Origin headers: %s", origin_headers)
    return origin_headers


def cors_main(url, method, headers, body):
    temp_headers = dict(headers)
    origin_headers = generate_origin(url)
    logs.logging.info("List of origin headers: %s", origin_headers)

    for origin in origin_headers:
        temp_headers['Origin'] = origin
        try:
            if method.upper() in ['GET', 'POST', 'PUT']:
                response = requests.options(url, headers=temp_headers, verify=False)
            else:
                response = requests.request(method.upper(), url, headers=temp_headers, verify=False)
            result = cors_check(origin, response.headers)
            if result:
                print(f"[+] {url} is vulnerable to cross-domain attack")
                return {
                    "url": url,
                    "alert": "CORS Misconfiguration",
                    "severity": result['impact'],
                    "req_headers": temp_headers,
                    "req_body": body,
                    "res_headers": dict(response.headers),
                    "res_body": "NA"
                }
        except Exception as e:
            logs.logging.error(f"Error during CORS check: {e}")

    logs.logging.info("Scan completed for cross-domain attack: %s", url)
    return {"result": "No CORS vulnerability found"}
