"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
# import json
# import subprocess
# import tempfile
# import re
# import os
# from urllib.parse import urlparse, parse_qs
#
# # Static list of SSRF payload elements
# SSRF_PAYLOADS = [
#     'dest', 'redirect', 'uri', 'path', 'continue', 'url', 'window',
#     'next', 'data', 'reference', 'site', 'html', 'val', 'validate',
#     'domain', 'callback', 'return', 'page', 'feed', 'host', 'port',
#     'to', 'out', 'view', 'dir'
# ]
#
#
# def parse_ssrfmap(output):
#     # Parse SSRFmap output
#     ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
#     output = output.decode("unicode-escape")
#     result = ansi_escape.sub('', output)
#     log = []
#     for line in result.split("\n"):
#         if 'open' in line or 'Reading file' in line:
#             log.append(line)
#     return log
#
#
# def create_file_content(parsed_url, method, headers, body):
#     # Create content for request
#     path = parsed_url.path
#     base_url = parsed_url.netloc
#     query = parsed_url.query
#     lines = []
#     if query:
#         lines.append(f"{method} {path}?{query} HTTP/1.1\n")
#     else:
#         lines.append(f"{method} {path} HTTP/1.1\n")
#     lines.append(f"Host: {base_url}\n")
#     for key, value in headers.items():
#         lines.append(f"{key}: {value}\n")
#     lines.append(str(body))
#     return lines
#
#
# def ssrf_check(url, method, headers, body):
#     try:
#         parsed_url = urlparse(url)
#         vuln_param = 'url'
#
#         # Determine parameter to test
#         if method == 'GET':
#             params = list(parse_qs(parsed_url.query).keys())
#         else:
#             params = list(body.keys())
#
#         if params:
#             vuln_param = next((param for param in params if param in SSRF_PAYLOADS), vuln_param)
#
#         content = create_file_content(parsed_url, method, headers, body)
#         with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
#             temp_file.writelines(content)
#             temp_file.seek(0)
#             fname = temp_file.name
#
#         # Run SSRFmap
#         scan_results = {}
#         if parsed_url.scheme == 'https':
#             proc = subprocess.Popen(
#                 ['python3', 'ssrfmap.py', '-r', fname, '-p', vuln_param, '-m', 'portscan,readfiles', '--ssl'],
#                 stdout=subprocess.PIPE, cwd='./SSRFmap')
#         else:
#             proc = subprocess.Popen(
#                 ['python3', 'ssrfmap.py', '-r', fname, '-p', vuln_param, '-m', 'portscan,readfiles'],
#                 stdout=subprocess.PIPE, cwd='./SSRFmap')
#
#         out, err = proc.communicate(timeout=900)
#         result = parse_ssrfmap(out)
#
#         if result:
#             scan_results = {
#                 "url": url,
#                 "alert": "Server-side request forgery",
#                 "severity": "High",
#                 "req_headers": headers,
#                 "req_body": body,
#                 "res_headers": "NA",
#                 "res_body": "NA",
#                 "log": "\n".join(result)
#             }
#
#         os.remove(fname)  # Clean up temporary file
#         return scan_results
#
#     except Exception as e:
#         return {"error": str(e)}

import json
import requests
from urllib.parse import urlparse, parse_qs

# Static list of SSRF payload elements
SSRF_PAYLOADS = [
    'dest', 'redirect', 'uri', 'path', 'continue', 'url', 'window',
    'next', 'data', 'reference', 'site', 'html', 'val', 'validate',
    'domain', 'callback', 'return', 'page', 'feed', 'host', 'port',
    'to', 'out', 'view', 'dir'
]


def generate_payloads(base_url, params):
    payloads = []
    for param in params:
        for payload in SSRF_PAYLOADS:
            payloads.append((param, f'http://localhost:8000/{payload}'))
    return payloads


def ssrf_check(url, method, headers, body):
    try:
        parsed_url = urlparse(url)
        params = list(parse_qs(parsed_url.query).keys()) if method == 'GET' else list(body.keys())

        if not params:
            return {"error": "No parameters found in the request to test for SSRF."}

        payloads = generate_payloads(parsed_url.netloc, params)
        scan_results = []

        for param, payload in payloads:
            test_url = url.replace(param, payload)
            response = requests.request(method, test_url, headers=headers, data=body)

            # Check if response contains potential SSRF indications
            if response.status_code == 200:
                scan_results.append({
                    "url": test_url,
                    "alert": "Potential SSRF vulnerability detected",
                    "response_status": response.status_code,
                    "response_body": response.text
                })

        if scan_results:
            return {
                "alert": "Server-side request forgery",
                "severity": "High",
                "scan_results": scan_results
            }
        else:
            return {"result": "No vulnerabilities found"}

    except Exception as e:
        return {"error": str(e)}
