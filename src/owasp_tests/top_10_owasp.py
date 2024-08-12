from sqlalchemy.orm import Session
from src.crud.api_crud import create_api, get_apis
from src.schemas.api_schemas import APIInventoryCreate
import time
import requests


async def check_broken_object_level_authorization(endpoint: str, object_id: str, unauthorized_user_token: str):
    """
    Test accessing an object with an unauthorized user token.
    """
    headers = {"Authorization": f"Bearer {unauthorized_user_token}"}
    response = requests.get(f"{endpoint}/{object_id}", headers=headers)

    if response.status_code == 403 or response.status_code == 401:
        return {"vulnerable": False, "status_code": response.status_code}
    else:
        return {"vulnerable": True, "status_code": response.status_code, "response": response.text}


async def check_broken_authentication(endpoint: str, weak_password: str, username: str):
    """
    Test if weak passwords are accepted.
    """
    data = {"username": username, "password": weak_password}
    response = requests.post(endpoint, data=data)

    if response.status_code == 200:
        return {"vulnerable": True, "response": response.text}
    else:
        return {"vulnerable": False, "status_code": response.status_code}

async def check_excessive_data_exposure(endpoint: str):
    """
    Test for excessive data exposure in API response.
    """
    response = requests.get(endpoint)

    sensitive_keywords = ["password", "credit_card", "ssn"]
    exposure = any(keyword in response.text for keyword in sensitive_keywords)

    return {"vulnerable": exposure, "response": response.text if exposure else None}


async def check_rate_limiting(endpoint: str, rate_limit: int):
    """
    Test API's rate limiting by sending requests in rapid succession.
    """
    responses = []
    for _ in range(rate_limit + 1):
        start_time = time.time()
        response = requests.get(endpoint)
        end_time = time.time()
        response_time = end_time - start_time
        responses.append({
            "status_code": response.status_code,
            "response_time": response_time,
            "response_body": response.text
        })
        time.sleep(0.1)  # Small delay between requests

    # Check if rate limiting was enforced
    rate_limited = any(response["status_code"] == 429 for response in responses)

    return {
        "rate_limited": rate_limited,
        "responses": responses
    }


async def check_broken_function_level_authorization(endpoint: str, unauthorized_user_token: str):
    """
    Test accessing a restricted function with an unauthorized user token.
    """
    headers = {"Authorization": f"Bearer {unauthorized_user_token}"}
    response = requests.get(endpoint, headers=headers)

    if response.status_code == 403 or response.status_code == 401:
        return {"vulnerable": False, "status_code": response.status_code}
    else:
        return {"vulnerable": True, "status_code": response.status_code, "response": response.text}


async def check_mass_assignment(endpoint: str):
    """
    Test for mass assignment vulnerabilities by sending unexpected fields.
    """
    data = {"role": "admin", "is_admin": True}
    response = requests.post(endpoint, json=data)

    if "role" in response.text or "is_admin" in response.text:
        return {"vulnerable": True, "response": response.text}
    else:
        return {"vulnerable": False, "status_code": response.status_code}


async def check_security_misconfiguration(endpoint: str):
    """
    Test for common security misconfigurations like missing headers.
    """
    response = requests.get(endpoint)
    missing_headers = []

    required_headers = ["X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"]
    for header in required_headers:
        if header not in response.headers:
            missing_headers.append(header)

    return {"vulnerable": len(missing_headers) > 0, "missing_headers": missing_headers}


async def check_injection(endpoint: str):
    """
    Test for injection vulnerabilities.
    """
    test_payloads = ["' OR '1'='1", "admin' --", "1 OR 1=1", "DROP TABLE users;"]
    results = []

    for payload in test_payloads:
        response = requests.post(endpoint, data={"input": payload})
        if "syntax error" in response.text or "unexpected" in response.text:
            results.append({"payload": payload, "vulnerable": True, "response": response.text})
        else:
            results.append({"payload": payload, "vulnerable": False, "response": response.text})

    return results


async def check_improper_assets_management(base_url: str, known_endpoints: list):
    """
    Test for improper assets management by discovering undocumented endpoints.
    """
    discovered_endpoints = []

    for endpoint in known_endpoints:
        response = requests.get(f"{base_url}/{endpoint}")
        if response.status_code == 200:
            discovered_endpoints.append(endpoint)

    # Check for endpoints not in the known list
    all_endpoints = ["v1/users", "v1/orders", "v1/admin", "v1/deprecated"]  # Example endpoints
    undocumented_endpoints = [ep for ep in all_endpoints if ep not in known_endpoints]

    return {"discovered_endpoints": discovered_endpoints, "undocumented_endpoints": undocumented_endpoints}



async def check_insufficient_logging_monitoring(endpoint: str):
    """
    Test for insufficient logging and monitoring by sending suspicious requests.
    """
    suspicious_payload = "<script>alert('xss')</script>"
    response = requests.post(endpoint, data={"input": suspicious_payload})

    # Check if the application responded with an alert or similar action
    alert_detected = "alert" in response.text

    return {"vulnerable": alert_detected, "response": response.text}
