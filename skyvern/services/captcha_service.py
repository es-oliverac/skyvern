import asyncio
import base64
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
    SLIDER_CAPTCHA = "slider"  # TikTok and similar slider puzzles


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
    slider_element: dict | None = Field(None, description="Slider element info for slider CAPTCHAs")


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

        # Check for TikTok/Generic Slider CAPTCHA
        # TikTok uses captcha-verify-container or secsdk-captcha
        slider_container = await page.query_selector(".captcha-verify-container, .secsdk-captcha-drag-icon, #captcha_slide_button, [class*='captcha'][class*='slider'], [class*='slide'][class*='captcha']")
        if slider_container:
            LOG.info("Detected Slider CAPTCHA (TikTok-style)")
            
            # Get slider button info
            slider_button = await page.query_selector("#captcha_slide_button, .secsdk-captcha-drag-icon, [class*='slider'][class*='button']")
            slider_info = None
            if slider_button:
                box = await slider_button.bounding_box()
                if box:
                    slider_info = {
                        "x": box["x"],
                        "y": box["y"],
                        "width": box["width"],
                        "height": box["height"],
                    }
            
            return CaptchaDetectionResult(
                captcha_type=CaptchaType.SLIDER_CAPTCHA,
                slider_element=slider_info
            )

        # Check for generic puzzle text indicators
        puzzle_text = await page.query_selector("text=Drag the slider, text=drag the puzzle, text=slide to verify, text=arrastra el control")
        if puzzle_text:
            LOG.info("Detected Slider CAPTCHA via text indicator")
            return CaptchaDetectionResult(captcha_type=CaptchaType.SLIDER_CAPTCHA)

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


async def capture_slider_screenshot(page: Page) -> str | None:
    """
    Capture screenshot of the slider CAPTCHA puzzle area.
    
    Returns:
        Base64 encoded image string, or None if failed
    """
    LOG.info("Capturing slider CAPTCHA screenshot")
    
    try:
        # Try to find the puzzle image container
        # TikTok uses various selectors for the puzzle image
        puzzle_selectors = [
            ".captcha-verify-container img",
            "[class*='captcha'] img",
            "canvas",
            "#captcha-verify-image",
            "[class*='puzzle'] img",
        ]
        
        for selector in puzzle_selectors:
            element = await page.query_selector(selector)
            if element:
                # Take screenshot of the element
                screenshot_bytes = await element.screenshot()
                base64_image = base64.b64encode(screenshot_bytes).decode('utf-8')
                LOG.info("Captured puzzle screenshot", selector=selector, size=len(base64_image))
                return base64_image
        
        # Fallback: capture the entire captcha container
        container = await page.query_selector(".captcha-verify-container, [class*='captcha'][class*='container']")
        if container:
            screenshot_bytes = await container.screenshot()
            base64_image = base64.b64encode(screenshot_bytes).decode('utf-8')
            LOG.info("Captured container screenshot", size=len(base64_image))
            return base64_image
        
        # Last resort: capture viewport
        screenshot_bytes = await page.screenshot()
        base64_image = base64.b64encode(screenshot_bytes).decode('utf-8')
        LOG.info("Captured full page screenshot", size=len(base64_image))
        return base64_image
        
    except Exception as e:
        LOG.error("Error capturing slider screenshot", error=str(e))
        return None


async def submit_slider_captcha(
    image_base64: str,
) -> str:
    """
    Submit slider/puzzle CAPTCHA to 2Captcha using coordinates method.

    Args:
        image_base64: Base64 encoded image of the puzzle

    Returns:
        The captcha_id for polling

    Raises:
        CaptchaSolvingFailed: If submission fails
    """
    LOG.info("Submitting Slider CAPTCHA to 2Captcha (coordinates method)")

    params = {
        "key": settings.TWOCAPTCHA_API_KEY,
        "method": "base64",
        "coordinatescaptcha": 1,
        "body": image_base64,
        "textinstructions": "Click on the center of the puzzle piece that needs to be moved",
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
                captcha_type=CaptchaType.SLIDER_CAPTCHA,
                reason=f"HTTP {status_code}",
            )

        if isinstance(response, dict):
            if response.get("status") == 1:  # Success
                captcha_id = response.get("request")
                LOG.info("Slider CAPTCHA submitted successfully", captcha_id=captcha_id)
                return captcha_id
            else:
                error_text = response.get("request", "Unknown error")
                raise CaptchaSolvingFailed(
                    captcha_type=CaptchaType.SLIDER_CAPTCHA,
                    reason=error_text,
                )
        else:
            raise CaptchaSolvingFailed(
                captcha_type=CaptchaType.SLIDER_CAPTCHA,
                reason="Invalid response format",
            )

    except CaptchaSolvingFailed:
        raise
    except Exception as e:
        LOG.error("Error submitting Slider CAPTCHA", error=str(e))
        raise CaptchaSolvingFailed(
            captcha_type=CaptchaType.SLIDER_CAPTCHA,
            reason=str(e),
        )


def parse_coordinates_response(request_data: Any) -> dict[str, int] | None:
    """
    Parse coordinates from 2Captcha response.
    
    2Captcha can return coordinates in multiple formats:
    - List of dicts: [{'x': '104', 'y': '115'}]
    - String: "coordinates:x=123,y=456"
    - String: "104,115"
    
    Args:
        request_data: The response from 2Captcha
        
    Returns:
        Dict with 'x' and 'y' as integers, or None if parsing fails
    """
    LOG.info("Parsing coordinates response", raw_data=request_data, data_type=type(request_data).__name__)
    
    try:
        # Handle list format: [{'x': '104', 'y': '115'}]
        if isinstance(request_data, list) and len(request_data) > 0:
            first_coord = request_data[0]
            if isinstance(first_coord, dict):
                x = first_coord.get('x')
                y = first_coord.get('y')
                if x is not None and y is not None:
                    # Convert to int (values might be strings)
                    coords = {"x": int(x), "y": int(y)}
                    LOG.info("Parsed coordinates from list format", coordinates=coords)
                    return coords
        
        # Handle dict format: {'x': 104, 'y': 115}
        if isinstance(request_data, dict):
            x = request_data.get('x')
            y = request_data.get('y')
            if x is not None and y is not None:
                coords = {"x": int(x), "y": int(y)}
                LOG.info("Parsed coordinates from dict format", coordinates=coords)
                return coords
        
        # Handle string formats
        if isinstance(request_data, str):
            # Format: "coordinates:x=123,y=456"
            if "coordinates:" in request_data:
                coords_str = request_data.replace("coordinates:", "")
                coords = {}
                for part in coords_str.split(","):
                    if "=" in part:
                        key, val = part.split("=")
                        coords[key.strip()] = int(val.strip())
                if "x" in coords and "y" in coords:
                    LOG.info("Parsed coordinates from 'coordinates:' format", coordinates=coords)
                    return coords
            
            # Format: "104,115" or "x=104,y=115"
            if "=" in request_data:
                coords = {}
                for part in request_data.split(","):
                    if "=" in part:
                        key, val = part.split("=")
                        coords[key.strip()] = int(val.strip())
                if "x" in coords and "y" in coords:
                    LOG.info("Parsed coordinates from key=value format", coordinates=coords)
                    return coords
            else:
                # Simple "x,y" format
                parts = request_data.split(",")
                if len(parts) >= 2:
                    coords = {"x": int(parts[0].strip()), "y": int(parts[1].strip())}
                    LOG.info("Parsed coordinates from simple format", coordinates=coords)
                    return coords
        
        LOG.warning("Could not parse coordinates", raw_data=request_data)
        return None
        
    except (ValueError, TypeError, KeyError) as e:
        LOG.error("Error parsing coordinates", error=str(e), raw_data=request_data)
        return None


async def get_solution(captcha_id: str, captcha_type: CaptchaType) -> dict[str, Any] | None:
    """
    Poll for CAPTCHA solution from 2Captcha.

    Args:
        captcha_id: The captcha_id returned from submit functions
        captcha_type: Type of CAPTCHA for logging

    Returns:
        dict with 'token' or 'coordinates' if solution is ready, None if not ready yet

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
                LOG.info("CAPTCHA solution ready", captcha_id=captcha_id, response=request_data)
                
                # For coordinates captcha, parse the response
                if captcha_type == CaptchaType.SLIDER_CAPTCHA:
                    coords = parse_coordinates_response(request_data)
                    if coords:
                        return {"coordinates": coords}
                    else:
                        # Return raw data as fallback
                        LOG.warning("Using raw coordinates data", raw_data=request_data)
                        return {"coordinates": request_data}
                
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
) -> dict[str, Any]:
    """
    Poll 2Captcha for CAPTCHA solution with timeout.

    Args:
        captcha_id: The captcha_id from submission
        captcha_type: Type of CAPTCHA being solved
        timeout: Maximum time to wait in seconds
        polling_interval: Time between polls in seconds

    Returns:
        The solution dict (token or coordinates)

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
            LOG.info("CAPTCHA solved successfully", captcha_id=captcha_id, solution=solution)
            return solution

        # Wait before next poll
        await asyncio.sleep(polling_interval)


async def solve_slider_with_drag(
    page: Page,
    coordinates: dict[str, int],
    slider_info: dict | None = None,
) -> bool:
    """
    Solve slider CAPTCHA by dragging the slider to the target position.

    Args:
        page: Playwright page instance
        coordinates: Target coordinates from 2Captcha {"x": int, "y": int}
        slider_info: Optional slider element info

    Returns:
        True if drag action was performed
    """
    LOG.info("Solving slider CAPTCHA with drag action", coordinates=coordinates)

    try:
        # Find the slider button
        slider_button = await page.query_selector("#captcha_slide_button, .secsdk-captcha-drag-icon, [class*='slider'][class*='button'], [class*='slide'][class*='btn']")
        
        if not slider_button:
            LOG.error("Could not find slider button")
            return False

        # Get slider bounding box
        box = await slider_button.bounding_box()
        if not box:
            LOG.error("Could not get slider bounding box")
            return False

        # Calculate start position (center of slider button)
        start_x = box["x"] + box["width"] / 2
        start_y = box["y"] + box["height"] / 2

        # Calculate end position
        # The x coordinate from 2Captcha represents where on the image the puzzle piece should go
        # We need to calculate how far to drag the slider
        target_x = coordinates.get("x", 0)
        
        # The slider starts at position ~32px (half of 64px button width)
        # The target_x is where on the screenshot the puzzle piece center should be
        # For TikTok slider, the puzzle piece moves with the slider 1:1
        # So move_distance = target_x - initial_puzzle_position
        # The puzzle piece usually starts around 20-30px from left edge
        move_distance = target_x - 32  # Approximate starting position of puzzle piece

        end_x = start_x + move_distance
        end_y = start_y  # Keep same Y

        LOG.info(
            "Performing slider drag",
            start_x=start_x,
            start_y=start_y,
            end_x=end_x,
            end_y=end_y,
            move_distance=move_distance,
            target_x=target_x,
        )

        # Perform the drag action with human-like movement
        await page.mouse.move(start_x, start_y)
        await asyncio.sleep(0.1)
        await page.mouse.down()
        await asyncio.sleep(0.05)

        # Move in steps to simulate human movement
        steps = 20
        for i in range(1, steps + 1):
            progress = i / steps
            current_x = start_x + (end_x - start_x) * progress
            # Add slight Y variation for realism
            current_y = start_y + (2 * (0.5 - abs(0.5 - progress)))
            await page.mouse.move(current_x, current_y)
            await asyncio.sleep(0.02)

        await page.mouse.move(end_x, end_y)
        await asyncio.sleep(0.1)
        await page.mouse.up()

        LOG.info("Slider drag completed")
        
        # Wait a moment for verification
        await asyncio.sleep(1)
        
        return True

    except Exception as e:
        LOG.error("Error performing slider drag", error=str(e))
        return False


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
        slider = await page.query_selector(".captcha-verify-container, #captcha_slide_button")

        # If neither CAPTCHA is present, the solution was likely accepted
        if not recaptcha and not hcaptcha and not slider:
            LOG.info("CAPTCHA solution accepted")
            return True

        LOG.info("CAPTCHA still present after injection/solving")
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
    4. Injects solution into page or performs drag action
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
    token = ""

    try:
        if captcha_type == CaptchaType.RECAPTCHA_V2:
            captcha_id = await submit_recaptcha_v2(site_key, page_url)
        elif captcha_type == CaptchaType.RECAPTCHA_V3:
            captcha_id = await submit_recaptcha_v3(site_key, page_url)
        elif captcha_type == CaptchaType.HCAPTCHA:
            captcha_id = await submit_hcaptcha(site_key, page_url)
        elif captcha_type == CaptchaType.SLIDER_CAPTCHA:
            # For slider captcha, we need to capture screenshot first
            image_base64 = await capture_slider_screenshot(page)
            if not image_base64:
                raise CaptchaSolvingFailed(
                    captcha_type=captcha_type,
                    reason="Failed to capture slider CAPTCHA screenshot",
                )
            captcha_id = await submit_slider_captcha(image_base64)
        else:
            raise CaptchaSolvingFailed(
                captcha_type=captcha_type,
                reason=f"CAPTCHA type {captcha_type} not yet supported",
            )

        # Step 3: Poll for solution
        solution = await poll_captcha_solution(
            captcha_id=captcha_id,
            captcha_type=captcha_type,
            timeout=timeout,
            polling_interval=settings.CAPTCHA_POLLING_INTERVAL_SECONDS,
        )

        end_time = datetime.utcnow()
        solving_time = (end_time - start_time).total_seconds()

        # Step 4: Apply solution
        if captcha_type in [CaptchaType.RECAPTCHA_V2, CaptchaType.RECAPTCHA_V3]:
            token = solution.get("token", "")
            await inject_recaptcha_token(page, token)
        elif captcha_type == CaptchaType.HCAPTCHA:
            token = solution.get("token", "")
            await inject_hcaptcha_token(page, token)
        elif captcha_type == CaptchaType.SLIDER_CAPTCHA:
            coordinates = solution.get("coordinates", {})
            LOG.info("Applying slider solution", coordinates=coordinates, coordinates_type=type(coordinates).__name__)
            
            if isinstance(coordinates, dict) and "x" in coordinates:
                drag_success = await solve_slider_with_drag(
                    page,
                    coordinates,
                    detection_result.slider_element,
                )
                token = f"slider_solved_x={coordinates.get('x')}_y={coordinates.get('y')}_success={drag_success}"
            else:
                LOG.warning("Invalid coordinates format, skipping drag", coordinates=coordinates)
                token = f"slider_invalid_coords_{coordinates}"

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
