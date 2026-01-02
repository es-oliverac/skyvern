import asyncio
import enum
from datetime import datetime, timedelta
from typing import Any

import structlog
from playwright.async_api import Page
from pydantic import BaseModel, Field

from skyvern.config import settings
from skyvern.exceptions import (
    CaptchaDetectionFailed,
    CaptchaInjectionFailed,
    CaptchaSolvingFailed,
    CaptchaSolutionNotFound,
    CaptchaTimeout,
)
from skyvern.forge.sdk.core.aiohttp_helper import aiohttp_request
from skyvern.webeye.scraper.scraped_page import ScrapedPage

LOG = structlog.get_logger()

# 2Captcha API endpoints
TWOCAPTCHA_BASE_URL = "http://2captcha.com"
TWOCAPTCHA_IN_URL = f"{TWOCAPTCHA_BASE_URL}/in.php"
TWOCAPTCHA_RES_URL = f"{TWOCAPTCHA_BASE_URL}/res.php"


class CaptchaType(str, enum.Enum):
    """Types of CAPTCHAs supported by the service"""

    RECAPTCHA_V2 = "recaptcha_v2"
    RECAPTCHA_V3 = "recaptcha_v3"
    HCAPTCHA = "hcaptcha"
    TEXT_CAPTCHA = "text"
    IMAGE_CAPTCHA = "image"


class CaptchaSolution(BaseModel):
    """Solution returned by the CAPTCHA solving service"""

    captcha_type: CaptchaType = Field(..., description="Type of CAPTCHA that was solved")
    token: str = Field(..., description="The solution token to inject into the page")
    captcha_id: str | None = Field(None, description="2Captcha task ID")
    solving_time_seconds: float | None = Field(None, description="Time taken to solve the CAPTCHA")


class CaptchaDetectionResult(BaseModel):
    """Result of CAPTCHA detection on a page"""

    captcha_type: CaptchaType | None = Field(None, description="Type of CAPTCHA detected")
    site_key: str | None = Field(None, description="Site key for reCAPTCHA/hCaptcha")
    element_id: str | None = Field(None, description="Element ID of the CAPTCHA widget")


async def detect_captcha_from_page(
    page: Page,
    scraped_page: ScrapedPage,
) -> CaptchaDetectionResult:
    """
    Detect CAPTCHA type and extract relevant information from the page.

    Args:
        page: Playwright page instance
        scraped_page: Scraped page data

    Returns:
        CaptchaDetectionResult with detected CAPTCHA type and parameters

    Raises:
        CaptchaDetectionFailed: If CAPTCHA detection fails
    """
    LOG.info("Detecting CAPTCHA type from page")

    try:
        # Check for reCAPTCHA (data-sitekey attribute)
        recaptcha_element = await page.query_selector("[data-sitekey]")
        if recaptcha_element:
            site_key = await recaptcha_element.get_attribute("data-sitekey")

            # Determine if it's reCAPTCHA v2 or v3
            # v3 is typically invisible and has size attribute set to "invisible"
            size_attr = await recaptcha_element.get_attribute("data-size")
            is_invisible = size_attr == "invisible"

            captcha_type = CaptchaType.RECAPTCHA_V3 if is_invisible else CaptchaType.RECAPTCHA_V2

            LOG.info(
                "Detected reCAPTCHA",
                captcha_type=captcha_type,
                site_key=site_key,
            )
            return CaptchaDetectionResult(captcha_type=captcha_type, site_key=site_key)

        # Check for hCaptcha
        hcaptcha_element = await page.query_selector(".h-captcha[data-sitekey]")
        if hcaptcha_element:
            site_key = await hcaptcha_element.get_attribute("data-sitekey")

            LOG.info("Detected hCaptcha", site_key=site_key)
            return CaptchaDetectionResult(captcha_type=CaptchaType.HCAPTCHA, site_key=site_key)

        LOG.info("No CAPTCHA detected on page")
        return CaptchaDetectionResult()

    except Exception as e:
        LOG.error("Error detecting CAPTCHA", error=str(e))
        raise CaptchaDetectionFailed(reason=f"Detection error: {str(e)}")


async def extract_page_url(page: Page) -> str:
    """Extract the current page URL"""
    return page.url


async def submit_recaptcha_v2(
    google_site_key: str,
    page_url: str,
    invisible: bool = False,
) -> str:
    """
    Submit reCAPTCHA v2 to 2Captcha for solving.

    Args:
        google_site_key: The site key from the reCAPTCHA widget
        page_url: The URL of the page with the CAPTCHA
        invisible: Whether this is an invisible reCAPTCHA

    Returns:
        The captcha_id for polling

    Raises:
        CaptchaSolvingFailed: If submission fails
    """
    LOG.info("Submitting reCAPTCHA v2 to 2Captcha", site_key=google_site_key, page_url=page_url)

    params = {
        "key": settings.TWOCAPTCHA_API_KEY,
        "method": "userrecaptcha",
        "googlekey": google_site_key,
        "pageurl": page_url,
        "json": 1,
    }

    if invisible:
        params["invisible"] = 1

    if settings.TWOCAPTCHA_SOFTWARE_KEY:
        params["soft_id"] = settings.TWOCAPTCHA_SOFTWARE_KEY

    try:
        status_code, headers, response = await aiohttp_request(
            "POST", TWOCAPTCHA_IN_URL, data=params
        )

        if status_code != 200:
            raise CaptchaSolvingFailed(
                captcha_type=CaptchaType.RECAPTCHA_V2,
                reason=f"HTTP {status_code}",
            )

        if isinstance(response, dict):
            if response.get("status") == 1:  # Success
                captcha_id = response.get("request")
                LOG.info("reCAPTCHA v2 submitted successfully", captcha_id=captcha_id)
                return captcha_id
            else:
                error_text = response.get("request", "Unknown error")
                raise CaptchaSolvingFailed(
                    captcha_type=CaptchaType.RECAPTCHA_V2,
                    reason=error_text,
                )
        else:
            raise CaptchaSolvingFailed(
                captcha_type=CaptchaType.RECAPTCHA_V2,
                reason="Invalid response format",
            )

    except CaptchaSolvingFailed:
        raise
    except Exception as e:
        LOG.error("Error submitting reCAPTCHA v2", error=str(e))
        raise CaptchaSolvingFailed(
            captcha_type=CaptchaType.RECAPTCHA_V2,
            reason=str(e),
        )


async def submit_recaptcha_v3(
    google_site_key: str,
    page_url: str,
) -> str:
    """
    Submit reCAPTCHA v3 to 2Captcha for solving.

    Args:
        google_site_key: The site key from the reCAPTCHA widget
        page_url: The URL of the page with the CAPTCHA

    Returns:
        The captcha_id for polling

    Raises:
        CaptchaSolvingFailed: If submission fails
    """
    LOG.info("Submitting reCAPTCHA v3 to 2Captcha", site_key=google_site_key, page_url=page_url)

    params = {
        "key": settings.TWOCAPTCHA_API_KEY,
        "method": "userrecaptcha",
        "version": "v3",
        "googlekey": google_site_key,
        "pageurl": page_url,
        "json": 1,
    }

    if settings.TWOCAPTCHA_SOFTWARE_KEY:
        params["soft_id"] = settings.TWOCAPTCHA_SOFTWARE_KEY

    try:
        status_code, headers, response = await aiohttp_request(
            "POST", TWOCAPTCHA_IN_URL, data=params
        )

        if status_code != 200:
            raise CaptchaSolvingFailed(
                captcha_type=CaptchaType.RECAPTCHA_V3,
                reason=f"HTTP {status_code}",
            )

        if isinstance(response, dict):
            if response.get("status") == 1:  # Success
                captcha_id = response.get("request")
                LOG.info("reCAPTCHA v3 submitted successfully", captcha_id=captcha_id)
                return captcha_id
            else:
                error_text = response.get("request", "Unknown error")
                raise CaptchaSolvingFailed(
                    captcha_type=CaptchaType.RECAPTCHA_V3,
                    reason=error_text,
                )
        else:
            raise CaptchaSolvingFailed(
                captcha_type=CaptchaType.RECAPTCHA_V3,
                reason="Invalid response format",
            )

    except CaptchaSolvingFailed:
        raise
    except Exception as e:
        LOG.error("Error submitting reCAPTCHA v3", error=str(e))
        raise CaptchaSolvingFailed(
            captcha_type=CaptchaType.RECAPTCHA_V3,
            reason=str(e),
        )


async def submit_hcaptcha(
    site_key: str,
    page_url: str,
) -> str:
    """
    Submit hCaptcha to 2Captcha for solving.

    Args:
        site_key: The site key from the hCaptcha widget
        page_url: The URL of the page with the CAPTCHA

    Returns:
        The captcha_id for polling

    Raises:
        CaptchaSolvingFailed: If submission fails
    """
    LOG.info("Submitting hCaptcha to 2Captcha", site_key=site_key, page_url=page_url)

    params = {
        "key": settings.TWOCAPTCHA_API_KEY,
        "method": "hcaptcha",
        "sitekey": site_key,
        "pageurl": page_url,
        "json": 1,
    }

    if settings.TWOCAPTCHA_SOFTWARE_KEY:
        params["soft_id"] = settings.TWOCAPTCHA_SOFTWARE_KEY

    try:
        status_code, headers, response = await aiohttp_request(
            "POST", TWOCAPTCHA_IN_URL, data=params
        )

        if status_code != 200:
            raise CaptchaSolvingFailed(
                captcha_type=CaptchaType.HCAPTCHA,
                reason=f"HTTP {status_code}",
            )

        if isinstance(response, dict):
            if response.get("status") == 1:  # Success
                captcha_id = response.get("request")
                LOG.info("hCaptcha submitted successfully", captcha_id=captcha_id)
                return captcha_id
            else:
                error_text = response.get("request", "Unknown error")
                raise CaptchaSolvingFailed(
                    captcha_type=CaptchaType.HCAPTCHA,
                    reason=error_text,
                )
        else:
            raise CaptchaSolvingFailed(
                captcha_type=CaptchaType.HCAPTCHA,
                reason="Invalid response format",
            )

    except CaptchaSolvingFailed:
        raise
    except Exception as e:
        LOG.error("Error submitting hCaptcha", error=str(e))
        raise CaptchaSolvingFailed(
            captcha_type=CaptchaType.HCAPTCHA,
            reason=str(e),
        )


async def get_solution(captcha_id: str, captcha_type: CaptchaType) -> dict[str, Any] | None:
    """
    Poll for CAPTCHA solution from 2Captcha.

    Args:
        captcha_id: The captcha_id returned from submit functions
        captcha_type: Type of CAPTCHA for logging

    Returns:
        dict with 'token' if solution is ready, None if not ready yet

    Raises:
        CaptchaSolvingFailed: If 2Captcha returns an error
    """
    # Build URL with query parameters directly (aiohttp_request doesn't support params=)
    url = f"{TWOCAPTCHA_RES_URL}?key={settings.TWOCAPTCHA_API_KEY}&action=get&id={captcha_id}&json=1"

    try:
        status_code, headers, response = await aiohttp_request(
            "GET", url
        )

        if status_code != 200:
            raise CaptchaSolvingFailed(
                captcha_type=captcha_type,
                reason=f"HTTP {status_code}",
            )

        if isinstance(response, dict):
            status = response.get("status")
            request_data = response.get("request")

            if status == 1:  # Solution is ready
                LOG.info("CAPTCHA solution ready", captcha_id=captcha_id)
                return {"token": request_data}
            elif request_data == "CAPCHA_NOT_READY":
                # Solution not ready yet, continue polling
                return None
            else:
                # Error from 2Captcha
                raise CaptchaSolvingFailed(
                    captcha_type=captcha_type,
                    reason=request_data or "Unknown error",
                )
        else:
            raise CaptchaSolvingFailed(
                captcha_type=captcha_type,
                reason="Invalid response format",
            )

    except CaptchaSolvingFailed:
        raise
    except Exception as e:
        LOG.error("Error polling for solution", error=str(e))
        raise CaptchaSolvingFailed(
            captcha_type=captcha_type,
            reason=str(e),
        )


async def poll_captcha_solution(
    captcha_id: str,
    captcha_type: CaptchaType,
    timeout: int = 120,
    polling_interval: int = 5,
) -> str:
    """
    Poll 2Captcha for CAPTCHA solution with timeout.

    Args:
        captcha_id: The captcha_id from submission
        captcha_type: Type of CAPTCHA being solved
        timeout: Maximum time to wait in seconds
        polling_interval: Time between polls in seconds

    Returns:
        The solution token

    Raises:
        CaptchaTimeout: If timeout is reached
        CaptchaSolvingFailed: If 2Captcha returns an error
    """
    start_time = datetime.utcnow()
    timeout_datetime = start_time + timedelta(seconds=timeout)

    LOG.info(
        "Polling for CAPTCHA solution",
        captcha_id=captcha_id,
        timeout_seconds=timeout,
        polling_interval_seconds=polling_interval,
    )

    while True:
        if datetime.utcnow() > timeout_datetime:
            LOG.warning("CAPTCHA solving timed out", captcha_id=captcha_id)
            raise CaptchaTimeout(captcha_type=captcha_type, timeout_seconds=timeout)

        solution = await get_solution(captcha_id, captcha_type)

        if solution:
            token = solution.get("token")
            LOG.info("CAPTCHA solved successfully", captcha_id=captcha_id)
            return token

        # Wait before next poll
        await asyncio.sleep(polling_interval)


async def inject_recaptcha_token(page: Page, token: str) -> None:
    """
    Inject reCAPTCHA token into the page.

    Args:
        page: Playwright page instance
        token: The solution token from 2Captcha

    Raises:
        CaptchaInjectionFailed: If injection fails
    """
    LOG.info("Injecting reCAPTCHA token")

    try:
        # Inject the token into the response textarea
        script = f"""
        (function() {{
            const responseElement = document.getElementById('g-recaptcha-response');
            if (responseElement) {{
                responseElement.innerHTML = '{token}';
            }}
            // Trigger callback if it exists
            if (typeof grecaptcha !== 'undefined' && grecaptcha.getResponse) {{
                grecaptcha.getResponse();
            }}
        }})();
        """
        await page.evaluate(script)
        LOG.info("reCAPTCHA token injected successfully")

    except Exception as e:
        LOG.error("Error injecting reCAPTCHA token", error=str(e))
        raise CaptchaInjectionFailed(
            captcha_type=CaptchaType.RECAPTCHA_V2,
            reason=str(e),
        )


async def inject_hcaptcha_token(page: Page, token: str) -> None:
    """
    Inject hCaptcha token into the page.

    Args:
        page: Playwright page instance
        token: The solution token from 2Captcha

    Raises:
        CaptchaInjectionFailed: If injection fails
    """
    LOG.info("Injecting hCaptcha token")

    try:
        # Inject the token into the response textarea
        script = f"""
        (function() {{
            const responseElement = document.getElementById('h-captcha-response');
            if (responseElement) {{
                responseElement.innerHTML = '{token}';
            }}
            // Trigger callback if it exists
            if (typeof hcaptcha !== 'undefined' && hcaptcha.getResponse) {{
                hcaptcha.getResponse();
            }}
        }})();
        """
        await page.evaluate(script)
        LOG.info("hCaptcha token injected successfully")

    except Exception as e:
        LOG.error("Error injecting hCaptcha token", error=str(e))
        raise CaptchaInjectionFailed(
            captcha_type=CaptchaType.HCAPTCHA,
            reason=str(e),
        )


async def verify_solution_accepted(page: Page) -> bool:
    """
    Verify that the CAPTCHA solution was accepted by checking if the CAPTCHA element is gone.

    Args:
        page: Playwright page instance

    Returns:
        True if solution was accepted, False otherwise
    """
    try:
        # Wait a bit for the page to process the solution
        await asyncio.sleep(2)

        # Check if CAPTCHA elements are still present
        recaptcha = await page.query_selector("[data-sitekey]")
        hcaptcha = await page.query_selector(".h-captcha[data-sitekey]")

        # If neither CAPTCHA is present, the solution was likely accepted
        if not recaptcha and not hcaptcha:
            LOG.info("CAPTCHA solution accepted")
            return True

        LOG.info("CAPTCHA still present after injection")
        return False

    except Exception as e:
        LOG.warning("Error verifying CAPTCHA solution", error=str(e))
        return False


async def solve_captcha(
    page: Page,
    scraped_page: ScrapedPage,
    task_id: str | None = None,
    step_id: str | None = None,
    timeout: int = 120,
) -> CaptchaSolution:
    """
    Main entry point for solving CAPTCHAs.

    This function:
    1. Detects CAPTCHA type and extracts parameters
    2. Submits to 2Captcha API
    3. Polls for solution
    4. Injects solution into page
    5. Verifies solution was accepted

    Args:
        page: Playwright page instance
        scraped_page: Scraped page data
        task_id: Optional task ID for logging
        step_id: Optional step ID for logging
        timeout: Maximum time to wait for solution in seconds

    Returns:
        CaptchaSolution with the solution token

    Raises:
        CaptchaDetectionFailed: If CAPTCHA detection fails
        CaptchaSolvingFailed: If submission or solving fails
        CaptchaTimeout: If solving times out
        CaptchaInjectionFailed: If solution injection fails
    """
    LOG.info(
        "Starting CAPTCHA solving process",
        task_id=task_id,
        step_id=step_id,
    )

    # Step 1: Detect CAPTCHA type
    detection_result = await detect_captcha_from_page(page, scraped_page)

    if not detection_result.captcha_type:
        raise CaptchaDetectionFailed(reason="No CAPTCHA detected on page")

    captcha_type = detection_result.captcha_type
    site_key = detection_result.site_key
    page_url = await extract_page_url(page)

    LOG.info(
        "CAPTCHA detected",
        captcha_type=captcha_type,
        site_key=site_key,
        page_url=page_url,
    )

    # Step 2: Submit to 2Captcha
    start_time = datetime.utcnow()

    try:
        if captcha_type == CaptchaType.RECAPTCHA_V2:
            captcha_id = await submit_recaptcha_v2(site_key, page_url)
        elif captcha_type == CaptchaType.RECAPTCHA_V3:
            captcha_id = await submit_recaptcha_v3(site_key, page_url)
        elif captcha_type == CaptchaType.HCAPTCHA:
            captcha_id = await submit_hcaptcha(site_key, page_url)
        else:
            raise CaptchaSolvingFailed(
                captcha_type=captcha_type,
                reason=f"CAPTCHA type {captcha_type} not yet supported",
            )

        # Step 3: Poll for solution
        token = await poll_captcha_solution(
            captcha_id=captcha_id,
            captcha_type=captcha_type,
            timeout=timeout,
            polling_interval=settings.CAPTCHA_POLLING_INTERVAL_SECONDS,
        )

        end_time = datetime.utcnow()
        solving_time = (end_time - start_time).total_seconds()

        # Step 4: Inject solution
        if captcha_type in [CaptchaType.RECAPTCHA_V2, CaptchaType.RECAPTCHA_V3]:
            await inject_recaptcha_token(page, token)
        elif captcha_type == CaptchaType.HCAPTCHA:
            await inject_hcaptcha_token(page, token)

        # Step 5: Verify solution (optional, best effort)
        await verify_solution_accepted(page)

        LOG.info(
            "CAPTCHA solved and injected successfully",
            captcha_type=captcha_type,
            solving_time_seconds=solving_time,
        )

        return CaptchaSolution(
            captcha_type=captcha_type,
            token=token,
            captcha_id=captcha_id,
            solving_time_seconds=solving_time,
        )

    except (CaptchaSolvingFailed, CaptchaTimeout) as e:
        # Re-raise known exceptions
        raise
    except Exception as e:
        LOG.exception("Unexpected error solving CAPTCHA")
        raise CaptchaSolvingFailed(
            captcha_type=captcha_type,
            reason=f"Unexpected error: {str(e)}",
        )
