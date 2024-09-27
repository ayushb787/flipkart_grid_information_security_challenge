"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
from urllib.parse import urlparse


def check_session_hijacking(uri, this_list, username, password):
    for keyword in this_list:
        if keyword in uri:
            return {
                "url": uri,
                "alert": "Session Fixation",
                "severity": "High",
                "req_headers": "NA",
                "req_body": "NA",
                "res_headers": "NA",
                "res_body": "NA"
            }
    return check_weak_password(password, uri)


def check_weak_password(password, uri):
    if password is None:
        return {
            "url": uri,
            "alert": "Weak Password",
            "severity": "High",
            "req_headers": "NA",
            "req_body": "NA",
            "res_headers": "NA",
            "res_body": "NA"
        }
    l, u, p, d = 0, 0, 0, 0
    s = password
    if len(s) >= 8:
        for i in s:
            if i.islower():
                l += 1
            if i.isupper():
                u += 1
            if i.isdigit():
                d += 1
            if i in {'@', '$', '_'}:
                p += 1
    if l >= 1 and u >= 1 and p >= 1 and d >= 1 and l + p + u + d == len(s):
        return None
    return {
        "url": uri,
        "alert": "Weak Password",
        "severity": "High",
        "req_headers": "NA",
        "req_body": "NA",
        "res_headers": "NA",
        "res_body": "NA"
    }


def broken_auth_check(uri, method, headers, body):
    this_list = ["sessionid=", "id=", "key="]
    parsed = urlparse(uri)
    username = parsed.username
    password = parsed.password
    result = check_session_hijacking(uri, this_list, username, password)
    if result:
        return result
    return {"result": "No vulnerabilities found"}

# Example Usage:
# result = broken_auth_check("http://example.com?sessionid=123", "GET", {}, {})
# print(result)
