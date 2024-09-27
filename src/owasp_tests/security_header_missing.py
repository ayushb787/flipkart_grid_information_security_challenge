"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import re
from loguru import logger
from . import sendrequest as req


def csp_check(url, method, req_headers, req_body, res_headers, res_body):
    if 'Content-Security-Policy' not in res_headers:
        return {"alert": "CSP Header Missing", "impact": "Low", "url": url}

def xss_protection_check(url, method, req_headers, req_body, res_headers, res_body):
    if 'X-XSS-Protection' not in res_headers:
        return {"alert": "X-XSS-Protection Header Missing", "impact": "Low", "url": url}
    else:
        xss_protection = res_headers['X-XSS-Protection'].replace(" ", "")
        if xss_protection == "0":
            return {"alert": "X-XSS-Protection Header Disabled", "impact": "Low", "url": url}
        elif xss_protection != "1;mode=block":
            return {"alert": "X-XSS-Protection Header not securely implemented", "impact": "Low", "url": url}

def x_frame_options_check(url, method, req_headers, req_body, res_headers, res_body):
    if 'X-Frame-Options' not in res_headers:
        return {"alert": "X-Frame-Options Header Missing", "impact": "Low", "url": url}

def hsts_check(url, method, req_headers, req_body, res_headers, res_body):
    if 'Strict-Transport-Security' not in res_headers:
        return {"alert": "Strict-Transport-Security Header Missing", "impact": "Low", "url": url}

def cookies_check(cookies, url, method, req_headers, req_body, res_headers, res_body):
    for cookie in cookies:
        if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
            return {"alert": "Cookie not marked secure or HttpOnly", "impact": "Low", "url": url}

def check_version_disclosure(url, method, req_headers, req_body, res_headers, res_body):
    version_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
    for each_version_header in version_headers:
        if each_version_header in res_headers:
            header_value = res_headers[each_version_header]
            if re.search('\d', header_value):  # Checks if the header has any digit.
                return {"alert": "Server Version Disclosure", "impact": "Low", "url": url}

def security_headers_missing(url, method, headers, body):
    # Perform the request
    resp = req.api_request(url, method, headers, body)
    if resp is None:
        return {"error": "API request failed or returned no response."}
    res_headers = resp.headers
    res_body = resp.text
    cookies = resp.cookies

    # Run checks
    checks = [
        csp_check(url, method, headers, body, res_headers, res_body),
        xss_protection_check(url, method, headers, body, res_headers, res_body),
        x_frame_options_check(url, method, headers, body, res_headers, res_body),
        hsts_check(url, method, headers, body, res_headers, res_body),
        cookies_check(cookies, url, method, headers, body, res_headers, res_body),
        check_version_disclosure(url, method, headers, body, res_headers, res_body)
    ]

    # Filter out None values
    results = [check for check in checks if check]

    if not results:
        return {"result": "No vulnerabilities found"}

    return results
