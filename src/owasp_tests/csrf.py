"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import configparser
import os
import random
import string
from urllib.parse import urlparse
import src.owasp_tests.sendrequest as req

request_headers = ['Accept',
                   'Accept-Charset',
                   'Accept-Encoding',
                   'Accept-Language',
                   'Accept-Datetime',
                   'Access-Control-Request-Method',
                   'Access-Control-Request-Headers',
                   'Authorization',
                   'Cache-Control',
                   'Connection',
                   'Cookie',
                   'Content-Length	',
                   'Content-MD5',
                   'Content-Type',
                   'Date',
                   'Expect',
                   'Forwarded',
                   'From',
                   'Host',
                   'If-Match',
                   'If-Modified-Since',
                   'If-None-Match',
                   'If-Range',
                   'If-Unmodified-Since',
                   'Max-Forwards',
                   'Origin',
                   'Pragma',
                   'Proxy-Authorization',
                   'Range',
                   'Referer',
                   'TE',
                   'User-Agent',
                   'Upgrade',
                   'Via',
                   'Warning'
                   'X-Requested-With'
                   'X-Forwarded-For',
                   'X-Forwarded-Host',
                   'X-Forwarded-Proto',
                   'X-Http-Method-Override',
                   'Proxy-Connection',
                   'X-Request-ID',
                   'X-Request-ID']

csrf_headers = [
    'X-Csrf-Token',
    'X-CSRFToken',
    'X-XSRF-TOKEN']


def get_value(filename, section, name):
    # Return only one value from config file
    if os.getcwd().split('/')[-1] == 'API':
        dir_name = '../utils/'
    else:
        dir_name = 'utils/'

    file_name = dir_name + filename
    Config = configparser.ConfigParser()
    Config.read(file_name)
    return Config.get(section, name)

def create_header_list(http_headers):
    return list(http_headers.keys())


def csrf_request(url, method, headers, body):
    try:
        http_request = req.api_request(url, method, headers, body)
        return http_request.status_code, len(http_request.text)
    except Exception as e:
        raise e


def csrf_header_remove(headers, csrf_header):
    headers.pop(csrf_header, None)
    return headers


def generate_csrf_token(csrf_header_value):
    length = len(csrf_header_value)
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def csrf_attack_body(url, method, headers, body, csrf_param):
    tmp_headers = headers.copy()
    http_status_code, response_size = csrf_request(url, method, headers, body)
    if csrf_param:
        body['csrf_param'] = generate_csrf_token(str(body['csrf_param']))

    csrf_req_body = req.api_request(url, method, headers, body)
    if csrf_req_body.status_code == http_status_code and len(csrf_req_body.text) == response_size:
        tmp_headers['Content-Type'] = 'text/plain'
        json_csrf = req.api_request(url, method, tmp_headers, body)
        impact = "High" if json_csrf.status_code != http_status_code or len(
            json_csrf.text) != response_size else "Medium"
        return {
            "url": url,
            "alert": "CSRF",
            "severity": impact,
            "req_headers": headers,
            "req_body": body,
            "res_headers": json_csrf.headers,
            "res_body": json_csrf.text
        }


def csrf_attack_header(url, method, headers, body, csrf_header):
    updated_headers = headers.copy()
    http_status_code, response_size = csrf_request(url, method, headers, body)
    updated_headers = csrf_header_remove(updated_headers, csrf_header)
    csrf_req = req.api_request(url, method, updated_headers, body)

    if csrf_req.status_code == http_status_code and len(csrf_req.text) == response_size:
        csrf_header_value = headers.get(csrf_header, '')
        headers[csrf_header] = generate_csrf_token(str(csrf_header_value))
        new_csrf_req = req.api_request(url, method, headers, body)
        if new_csrf_req.status_code == http_status_code and len(new_csrf_req.text) == response_size:
            return {
                "url": url,
                "alert": "CSRF",
                "impact": "High",
                "req_headers": headers,
                "req_body": body,
                "res_headers": new_csrf_req.headers,
                "res_body": new_csrf_req.text
            }

    return None


def fetch_csrf_names():
    return get_value('scan.property', 'modules', 'csrftoken-names').split(',')


def verify_body(body):
    common_names = fetch_csrf_names()
    for csrf_name in common_names:
        if csrf_name in body:
            return csrf_name
    return None


def verify_headers(headers):
    headers_list = create_header_list(headers)
    for common_header in csrf_headers:
        if common_header in headers_list:
            return common_header

    for http_header in headers_list:
        if http_header not in request_headers:
            return http_header

    return None


def csrf_check(url, method, headers, body):
    if method in ["POST", "PUT", "DEL"]:
        csrf_header = verify_headers(headers)
        if csrf_header:
            return csrf_attack_header(url, method, headers, body, csrf_header)
        else:
            csrf_param = verify_body(body)
            return csrf_attack_body(url, method, headers, body, csrf_param) if csrf_param else csrf_attack_body(url,
                                                                                                                method,
                                                                                                                headers,
                                                                                                                body,
                                                                                                                None)

    return {"result": "No vulnerabilities found"}

# Example Usage:
# result = csrf_check("http://example.com", "POST", {"X-CSRF-TOKEN": "token"}, {"csrf_param": "value"})
# print(result)
