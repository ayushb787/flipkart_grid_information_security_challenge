"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import os
import configparser
import random
import string
import src.owasp_tests.sendrequest as req


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


def generate_list(length, type):
    # Generate different possible parameter values for brute force
    if type == 'int':
        length = '%0' + str(length) + 'd'
        return [length % x for x in range(50)]
    elif type == 'str':
        return [''.join(random.choice(string.ascii_letters) for _ in range(length)) for _ in range(50)]
    return []


def brute_force(url, method, headers, body, attack_params):
    failed_set = ['exceed', 'captcha', 'too many', 'rate limit', 'Maximum login']
    if len(attack_params) == 1:
        param_value = body.get(attack_params[0])
        if param_value is None:
            return None

        brute_list = generate_list(len(str(param_value)), 'int' if isinstance(param_value, int) else 'str')
        http_len = None
        result = None

        for value in brute_list:
            body[attack_params[0]] = value
            if get_value('config.property', 'login', 'auth_type') == "cookie":
                headers.pop('Cookie', None)

            brute_request = req.api_request(url, method, headers, body)
            if brute_request is not None:
                if http_len is None:
                    http_len = len(brute_request.text)

                if len(brute_request.text) == http_len:
                    if str(brute_request.status_code).startswith(('2', '4')):
                        if any(failed_name in brute_request.text for failed_name in failed_set):
                            result = {
                                "url": url,
                                "alert": "Rate Limit Protection Detected",
                                "severity": "High",
                                "req_headers": headers,
                                "req_body": body,
                                "res_headers": brute_request.headers,
                                "res_body": brute_request.text
                            }
                        else:
                            result = {
                                "url": url,
                                "alert": "Missing Rate Limit",
                                "severity": "High",
                                "req_headers": headers,
                                "req_body": body,
                                "res_headers": brute_request.headers,
                                "res_body": brute_request.text
                            }
        return result


def rate_limit(url, method, headers, body):
    if method in ["POST", "PUT"] and body:
        param_names = ['pin', 'password', 'cvv', 'pass', 'otp']
        attack_params = [name.lower() for name in param_names if
                         any(name.lower() == key.lower() for key in body.keys())]

        if attack_params:
            return brute_force(url, method, headers, body, attack_params)

    return {"result": "No vulnerabilities found"}

# Example Usage:
# result = rate_limit("http://example.com", "POST", {}, {"password": "test"})
# print(result)
