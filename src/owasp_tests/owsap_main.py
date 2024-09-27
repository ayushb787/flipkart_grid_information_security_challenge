"""
Author: Ayush Bhandari
Email: ayushbhandariofficial@gmail.com
"""
import json
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict
import json

from src.db.alchemy import SessionLocal
from src.models.api_models import SecurityIssue, SecurityTestResult
from src.owasp_tests.broken_auth import broken_auth_check
from src.owasp_tests.cors import cors_check, cors_main
from src.owasp_tests.crlf import crlf_check
from src.owasp_tests.csrf import csrf_check
from src.owasp_tests.jwt_check import jwt_check
from src.owasp_tests.rate_limiting import rate_limit
from src.owasp_tests.redirect import check_open_redirect
from src.owasp_tests.security_header_missing import security_headers_missing
from src.owasp_tests.ssrf import ssrf_check
from fastapi import APIRouter

from src.owasp_tests.xss import xss_check
from src.owasp_tests.xxe import  xxe_test

router = APIRouter()


def modules_scan(url, method, headers, body):
    results = {}

    # Perform each check and collect results
    results['SSRF'] = perform_check(ssrf_check, url, method, headers, body)
    results['CORS'] = perform_check(cors_main, url, method, headers, body)
    results['Broken Authentication'] = perform_check(broken_auth_check, url, method, headers, body)
    results['Rate Limit'] = perform_check(rate_limit, url, method, headers, body)
    results['CSRF'] = perform_check(csrf_check, url, method, headers, body)
    results['JWT'] = perform_check(jwt_check, url, method, headers, body)
    # results['SQL Injection'] = perform_check(sqli_check, url, method, headers, body) #Not Working
    results['XSS'] = perform_check(xss_check, url, method, headers, body)
    results['Open Redirect'] = perform_check(check_open_redirect, url, method, headers, body)
    results['XXE'] = perform_check( xxe_test, url, method, headers, body)
    results['CRLF'] = perform_check(crlf_check, url, method, headers, body)
    results['Security Headers'] = perform_check(security_headers_missing, url, method, headers, body)

    # Return results as JSON
    return json.dumps(results, indent=4)

# def modules_scan(api_inventory_id: int, url: str, method: str, headers: dict, body: dict):
#     session = SessionLocal()
#     try:
#         # Perform each check and collect results
#         results = {
#             'SSRF': perform_check(ssrf_check, url, method, headers, body),
#             'CORS': perform_check(cors_main, url, method, headers, body),
#             'Broken Authentication': perform_check(broken_auth_check, url, method, headers, body),
#             'Rate Limit': perform_check(rate_limit, url, method, headers, body),
#             'CSRF': perform_check(csrf_check, url, method, headers, body),
#             'JWT': perform_check(jwt_check, url, method, headers, body),
#             'XSS': perform_check(xss_check, url, method, headers, body),
#             'Open Redirect': perform_check(check_open_redirect, url, method, headers, body),
#             'XXE': perform_check(xxe_test, url, method, headers, body),
#             'CRLF': perform_check(crlf_check, url, method, headers, body),
#             'Security Headers': perform_check(security_headers_missing, url, method, headers, body),
#         }
#
#         # Store the results in the database
#         test_results = SecurityTestResult(
#             api_inventory_id=api_inventory_id,
#             endpoint=url,
#             ssrf=results['SSRF'],
#             cors=results['CORS'],
#             broken_auth=results['Broken Authentication'],
#             rate_limit=results['Rate Limit'],
#             csrf=results['CSRF'],
#             jwt=results['JWT'],
#             xss=results['XSS'],
#             open_redirect=results['Open Redirect'],
#             xxe=results['XXE'],
#             crlf=results['CRLF'],
#             security_headers=results['Security Headers'],
#         )
#
#         session.add(test_results)
#
#         # Handle results and log issues
#         issues = []
#
#         def handle_results(results, description, severity):
#             if isinstance(results, dict) and results.get('vulnerable'):
#                 issues.append((description, severity))
#             elif isinstance(results, list):
#                 for result in results:
#                     if isinstance(result, dict) and result.get('vulnerable'):
#                         issues.append((description, severity))
#
#         # Map results to issues with descriptions and severity
#         handle_results(results['SSRF'], "SSRF Vulnerability", "High")
#         handle_results(results['CORS'], "CORS Misconfiguration", "Medium")
#         handle_results(results['Broken Authentication'], "Broken Authentication", "High")
#         handle_results(results['Rate Limit'], "Rate Limiting Issue", "Medium")
#         handle_results(results['CSRF'], "CSRF Vulnerability", "High")
#         handle_results(results['JWT'], "JWT Vulnerability", "Medium")
#         handle_results(results['XSS'], "XSS Vulnerability", "High")
#         handle_results(results['Open Redirect'], "Open Redirect Vulnerability", "Medium")
#         handle_results(results['XXE'], "XXE Vulnerability", "High")
#         handle_results(results['CRLF'], "CRLF Injection", "Medium")
#         handle_results(results['Security Headers'], "Missing Security Headers", "Low")
#
#         # Store the issues in the database
#         for issue_description, severity in issues:
#             security_issue = SecurityIssue(
#                 api_inventory_id=api_inventory_id,
#                 endpoint=url,
#                 issue_description=issue_description,
#                 severity=severity,
#                 status="open"
#             )
#             session.add(security_issue)
#
#         session.commit()
#         return json.dumps(results, indent=4)
#
#     except Exception as e:
#         session.rollback()
#         raise HTTPException(status_code=500, detail=str(e))
#     finally:
#         session.close()

def perform_check(check_func, url, method, headers, body):
    """
    Perform the security check using the provided function and return the result.
    """
    try:
        return check_func(url, method, headers, body)
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}
def perform_check(check_function, url, method, headers, body):
    try:
        # Call the check function and return its result
        return check_function(url, method, headers, body)
    except Exception as e:
        # Handle any exceptions and return an error message
        return {"error": str(e)}


class ScanRequest(BaseModel):
    url: str
    method: str
    headers: Optional[Dict[str, str]] = None
    body: Optional[Dict[str, str]] = None

@router.post("/scan")
async def scan_endpoint(scan_request: ScanRequest):
    # Convert the Pydantic model to dictionary
    url = scan_request.url
    method = scan_request.method
    headers = scan_request.headers or {}
    body = scan_request.body or {}


    # Call the modules_scan function
    results = modules_scan(
        url=url,
        method=method,
        headers=headers,
        body=body,
    )

    # Return the results as JSON
    return json.loads(results)