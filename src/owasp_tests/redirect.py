"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
from . import sendrequest as req
import urllib.parse

# Define the redirection URL to test against
redirection_url = "www.google.com"

# List of open redirect payloads directly included
redirect_payloads = [
    "?url=http://{target}",
    "?url=https://{target}",
    "?next=http://{target}",
    "?next=https://{target}",
    "?url=//{target}",
    "?url=$2f%2f{target}",
    "?next=//{target}",
    "?next=$2f%2f{target}",
    "/redirect/{target}",
    "/cgi-bin/redirect.cgi?{target}",
    "/out/{target}",
    "/out?{target}",
    "/out?/{target}",
    "/out?//{target}",
    "?view={target}",
    "?view=/{target}",
    "/login?to={target}",
    "/login?to=/{target}",
    "{target}",
    "//google.com/%2f..",
    "https://google.com/%2f%2e%2e",
    "/google.com/%2f%2e%2e",
    "//google.com/",
    "http://;@google.com"
]

def fetch_redirection_names():
    # Hard-coded list of common open redirection param names
    return ['url', 'redirect', 'next']

def check_open_redirect(url, method, headers, body):
    results = []

    # Check for POST based open redirection
    if method == 'POST':
        temp_body = {}
        param_names = fetch_redirection_names()
        for key, value in body.items():
            if key in param_names:
                for payload in redirect_payloads:
                    if "=" in payload:
                        payload = payload[payload.find('=')+1:].replace('{target}', redirection_url)
                    else:
                        payload = payload.replace('{target}', redirection_url)

                    temp_body.update(body)
                    temp_body[key] = payload
                    post_req = req.api_request(url, "POST", headers, temp_body)
                    if str(post_req.status_code)[0] == '3':
                        if post_req.headers.get('Location', '').startswith(redirection_url):
                            results.append({
                                "url": url,
                                "alert": "Open redirection",
                                "severity": "Medium",
                                "req_headers": headers,
                                "req_body": body,
                                "res_headers": post_req.headers,
                                "res_body": "NA"
                            })

    # Check for URI based redirection
    if method == 'GET':
        url_query = urllib.parse.urlparse(url)
        parsed_query = urllib.parse.parse_qs(url_query.query)
        for key, value in parsed_query.items():
            if key in fetch_redirection_names():
                for payload in redirect_payloads:
                    if '=' in payload:
                        payload = payload[payload.find('=')+1:].replace('{target}', redirection_url)
                    else:
                        payload = payload.replace('{target}', redirection_url)
                    redirect_url = f"{url_query.scheme}://{url_query.netloc}{url_query.path}/?{url_query.query.replace(value[0], payload)}"
                    fuzz_req = req.api_request(redirect_url, "GET", headers)
                    if str(fuzz_req.status_code)[0] == '3':
                        if fuzz_req.headers.get('Location', '').startswith(redirection_url):
                            results.append({
                                "url": redirect_url,
                                "alert": "Open redirection",
                                "severity": "Medium",
                                "req_headers": headers,
                                "req_body": body,
                                "res_headers": fuzz_req.headers,
                                "res_body": "NA"
                            })

    # Fuzzing target URL with different params
    parsed_url = urllib.parse.urlparse(url)
    target_domain = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rstrip('/')}"
    for payload in redirect_payloads:
        try:
            target_url = f"{target_domain}{payload.replace('{target}', redirection_url)}"
        except:
            target_url = f"{target_domain}{payload}"
        fuzz_req = req.api_request(target_url, "GET", headers)
        if str(fuzz_req.status_code // 100) == '3':
            location_header = fuzz_req.headers.get('Location', '')
            if "google" in location_header.lower() or location_header.startswith(redirection_url):
                results.append({
                    "url": target_url,
                    "alert": "Open redirection",
                    "severity": "Medium",
                    "req_headers": headers,
                    "req_body": body,
                    "res_headers": fuzz_req.headers,
                    "res_body": "NA"
                })

    return results
