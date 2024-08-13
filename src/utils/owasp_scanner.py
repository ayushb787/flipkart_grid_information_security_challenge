from fastapi import HTTPException
from datetime import datetime

from src.db.alchemy import SessionLocal, AsyncSessionLocal
from src.models.api_models import SecurityTestResult, SecurityIssue
from src.owasp_tests.top_10_owasp import check_insufficient_logging_monitoring, check_improper_assets_management, check_injection, \
    check_security_misconfiguration, check_mass_assignment, check_broken_function_level_authorization, \
    check_rate_limiting, check_excessive_data_exposure, check_broken_object_level_authorization, \
    check_broken_authentication

async def run_all_security_tests(api_inventory_id: int, endpoint: str):
    """
    Run all OWASP Top 10 security tests and store results in the database.
    """
    session = SessionLocal()
    try:
        auth_results = await check_broken_authentication(endpoint, weak_password="123456", username="test_user")
        bola_results = await check_broken_object_level_authorization(endpoint, object_id="1", unauthorized_user_token="unauth_token")
        data_exposure_results = await check_excessive_data_exposure(endpoint)
        rate_limit_results = await check_rate_limiting(endpoint, rate_limit=10)
        function_auth_results = await check_broken_function_level_authorization(endpoint, unauthorized_user_token="unauth_token")
        mass_assignment_results = await check_mass_assignment(endpoint)
        security_misconfig_results = await check_security_misconfiguration(endpoint)
        injection_results = await check_injection(endpoint)
        asset_management_results = await check_improper_assets_management(base_url=endpoint, known_endpoints=["v1/users", "v1/orders"])
        logging_monitoring_results = await check_insufficient_logging_monitoring(endpoint)

        test_results = SecurityTestResult(
            api_inventory_id=api_inventory_id,
            endpoint=endpoint,
            broken_auth=auth_results,
            bola=bola_results,
            excessive_data_exposure=data_exposure_results,
            rate_limiting=rate_limit_results,
            function_auth=function_auth_results,
            mass_assignment=mass_assignment_results,
            security_misconfig=security_misconfig_results,
            injection=injection_results,
            asset_management=asset_management_results,
            logging_monitoring=logging_monitoring_results,
        )

        session.add(test_results)

        issues = []

        def handle_results(results, description, severity):
            if isinstance(results, dict) and results.get('vulnerable'):
                issues.append((description, severity))
            elif isinstance(results, list):  # If results is a list
                for result in results:
                    if isinstance(result, dict) and result.get('vulnerable'):
                        issues.append((description, severity))

        # Use the handling function for each test
        handle_results(auth_results, "Broken Authentication", "High")
        handle_results(bola_results, "Broken Object Level Authorization", "High")
        handle_results(data_exposure_results, "Excessive Data Exposure", "Medium")
        handle_results(rate_limit_results, "Rate Limiting Issue", "Medium")
        handle_results(function_auth_results, "Broken Function Level Authorization", "High")
        handle_results(mass_assignment_results, "Mass Assignment", "Medium")
        handle_results(security_misconfig_results, "Security Misconfiguration", "High")
        handle_results(injection_results, "Injection Vulnerability", "Critical")
        handle_results(asset_management_results, "Improper Asset Management", "Medium")
        handle_results(logging_monitoring_results, "Insufficient Logging & Monitoring", "Medium")

        for issue_description, severity in issues:
            security_issue = SecurityIssue(
                api_inventory_id=api_inventory_id,
                endpoint=endpoint,
                issue_description=issue_description,
                severity=severity,
                status="open"
            )
            session.add(security_issue)

        session.commit()
        # return {
        #     "test_results": test_results,
        #     "issues": issues,
        # }
        return {"message": "Security test results and issues stored in database successfully."}

    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()
