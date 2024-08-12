from fastapi import HTTPException
from datetime import datetime

from src.db.alchemy import SessionLocal
from src.models.api_models import SecurityTestResult
from src.owasp_tests.top_10_owasp import check_insufficient_logging_monitoring, check_improper_assets_management, check_injection, \
    check_security_misconfiguration, check_mass_assignment, check_broken_function_level_authorization, \
    check_rate_limiting, check_excessive_data_exposure, check_broken_object_level_authorization, \
    check_broken_authentication


def log_results(results, endpoint):
    """
    Return the results of the security owasp_tests as a JSON object.
    """
    results_with_metadata = {
        "endpoint": endpoint,
        "scan_timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "results": results
    }

    return results_with_metadata



async def run_all_security_tests(endpoint: str):
    """
    Run all OWASP Top 10 security owasp_tests and store the results in the database.
    """
    session = SessionLocal()
    try:
        auth_results = await check_broken_authentication(endpoint, weak_password="123456", username="test_user")
        bola_results = await check_broken_object_level_authorization(endpoint, object_id="1",
                                                                     unauthorized_user_token="unauth_token")
        data_exposure_results = await check_excessive_data_exposure(endpoint)
        rate_limit_results = await check_rate_limiting(endpoint, rate_limit=10)
        function_auth_results = await check_broken_function_level_authorization(endpoint,
                                                                                unauthorized_user_token="unauth_token")
        mass_assignment_results = await check_mass_assignment(endpoint)
        security_misconfig_results = await check_security_misconfiguration(endpoint)
        injection_results = await check_injection(endpoint)
        asset_management_results = await check_improper_assets_management(base_url=endpoint,
                                                                          known_endpoints=["v1/users", "v1/orders"])
        logging_monitoring_results = await check_insufficient_logging_monitoring(endpoint)

        results = SecurityTestResult(
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

        session.add(results)
        session.commit()

        return {"message": "Security test results stored in database successfully."}

    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()
