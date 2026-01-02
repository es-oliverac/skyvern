import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from skyvern.services.captcha_service import (
    CaptchaType,
    CaptchaSolution,
    CaptchaDetectionResult,
    detect_captcha_from_page,
    extract_page_url,
    submit_recaptcha_v2,
    submit_recaptcha_v3,
    submit_hcaptcha,
    get_solution,
    poll_captcha_solution,
    inject_recaptcha_token,
    inject_hcaptcha_token,
    verify_solution_accepted,
    solve_captcha,
)


@pytest.mark.asyncio
async def test_detect_recaptcha_v2():
    """Test detection of reCAPTCHA v2"""
    mock_page = MagicMock()
    mock_element = MagicMock()

    # Mock reCAPTCHA element
    mock_page.query_selector.return_value = mock_element
    mock_element.get_attribute.side_effect = lambda attr: "6Le-wvkSAAAA" if attr == "data-sitekey" else None

    mock_scraped_page = MagicMock()

    result = await detect_captcha_from_page(mock_page, mock_scraped_page)

    assert result.captcha_type == CaptchaType.RECAPTCHA_V2
    assert result.site_key == "6Le-wvkSAAAA"


@pytest.mark.asyncio
async def test_detect_recaptcha_v3():
    """Test detection of reCAPTCHA v3 (invisible)"""
    mock_page = MagicMock()
    mock_element = MagicMock()

    # Mock reCAPTCHA element with size="invisible"
    mock_page.query_selector.return_value = mock_element
    mock_element.get_attribute.side_effect = lambda attr: "invisible" if attr == "data-size" else "6Le-wvkSAAAA"

    mock_scraped_page = MagicMock()

    result = await detect_captcha_from_page(mock_page, mock_scraped_page)

    assert result.captcha_type == CaptchaType.RECAPTCHA_V3
    assert result.site_key == "6Le-wvkSAAAA"


@pytest.mark.asyncio
async def test_detect_hcaptcha():
    """Test detection of hCaptcha"""
    mock_page = MagicMock()
    mock_recaptcha = None  # No reCAPTCHA
    mock_hcaptcha = MagicMock()

    # Mock queries
    async def mock_query_selector(selector):
        if "[data-sitekey]" in selector:
            return None
        if ".h-captcha" in selector:
            return mock_hcaptcha
        return None

    mock_page.query_selector = mock_query_selector
    mock_hcaptcha.get_attribute.return_value = "a5f74b19-1234-5678-90ab-cdef12345678"

    mock_scraped_page = MagicMock()

    result = await detect_captcha_from_page(mock_page, mock_scraped_page)

    assert result.captcha_type == CaptchaType.HCAPTCHA
    assert result.site_key == "a5f74b19-1234-5678-90ab-cdef12345678"


@pytest.mark.asyncio
async def test_detect_no_captcha():
    """Test when no CAPTCHA is present"""
    mock_page = MagicMock()
    mock_page.query_selector.return_value = None

    mock_scraped_page = MagicMock()

    result = await detect_captcha_from_page(mock_page, mock_scraped_page)

    assert result.captcha_type is None
    assert result.site_key is None


@pytest.mark.asyncio
async def test_extract_page_url():
    """Test extracting page URL"""
    mock_page = MagicMock()
    mock_page.url = "https://example.com/page"

    url = await extract_page_url(mock_page)

    assert url == "https://example.com/page"


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.aiohttp_request")
@patch("skyvern.services.captcha_service.settings")
async def test_submit_recaptcha_v2_success(mock_settings, mock_aiohttp_request):
    """Test successful submission of reCAPTCHA v2"""
    mock_settings.TWOCAPTCHA_API_KEY = "test_api_key"
    mock_settings.TWOCAPTCHA_SOFTWARE_KEY = None

    # Mock successful response
    mock_aiohttp_request.return_value = (200, {}, {"status": 1, "request": "captcha_id_123"})

    captcha_id = await submit_recaptcha_v2(
        google_site_key="6Le-wvkSAAAA",
        page_url="https://example.com",
    )

    assert captcha_id == "captcha_id_123"


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.aiohttp_request")
@patch("skyvern.services.captcha_service.settings")
async def test_submit_recaptcha_v3_success(mock_settings, mock_aiohttp_request):
    """Test successful submission of reCAPTCHA v3"""
    mock_settings.TWOCAPTCHA_API_KEY = "test_api_key"
    mock_settings.TWOCAPTCHA_SOFTWARE_KEY = None

    # Mock successful response
    mock_aiohttp_request.return_value = (200, {}, {"status": 1, "request": "captcha_id_456"})

    captcha_id = await submit_recaptcha_v3(
        google_site_key="6Le-wvkSAAAA",
        page_url="https://example.com",
    )

    assert captcha_id == "captcha_id_456"


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.aiohttp_request")
@patch("skyvern.services.captcha_service.settings")
async def test_submit_hcaptcha_success(mock_settings, mock_aiohttp_request):
    """Test successful submission of hCaptcha"""
    mock_settings.TWOCAPTCHA_API_KEY = "test_api_key"
    mock_settings.TWOCAPTCHA_SOFTWARE_KEY = None

    # Mock successful response
    mock_aiohttp_request.return_value = (200, {}, {"status": 1, "request": "captcha_id_789"})

    captcha_id = await submit_hcaptcha(
        site_key="a5f74b19-1234-5678-90ab-cdef12345678",
        page_url="https://example.com",
    )

    assert captcha_id == "captcha_id_789"


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.aiohttp_request")
@patch("skyvern.services.captcha_service.settings")
async def test_get_solution_ready(mock_settings, mock_aiohttp_request):
    """Test getting a ready CAPTCHA solution"""
    mock_settings.TWOCAPTCHA_API_KEY = "test_api_key"

    # Mock successful solution response
    mock_aiohttp_request.return_value = (200, {}, {"status": 1, "request": "solution_token_abc"})

    solution = await get_solution("captcha_id_123", CaptchaType.RECAPTCHA_V2)

    assert solution is not None
    assert solution["token"] == "solution_token_abc"


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.aiohttp_request")
@patch("skyvern.services.captcha_service.settings")
async def test_get_solution_not_ready(mock_settings, mock_aiohttp_request):
    """Test getting solution when not ready yet"""
    mock_settings.TWOCAPTCHA_API_KEY = "test_api_key"

    # Mock CAPTCHA_NOT_READY response
    mock_aiohttp_request.return_value = (200, {}, {"status": 0, "request": "CAPCHA_NOT_READY"})

    solution = await get_solution("captcha_id_123", CaptchaType.RECAPTCHA_V2)

    assert solution is None


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.get_solution")
@patch("skyvern.services.captcha_service.asyncio.sleep")
async def test_poll_captcha_solution_success(mock_sleep, mock_get_solution):
    """Test successful polling for CAPTCHA solution"""
    # First call returns None (not ready), second returns solution
    mock_get_solution.side_effect = [None, {"token": "solution_token_xyz"}]

    token = await poll_captcha_solution(
        captcha_id="captcha_id_123",
        captcha_type=CaptchaType.RECAPTCHA_V2,
        timeout=120,
        polling_interval=1,
    )

    assert token == "solution_token_xyz"
    assert mock_get_solution.call_count == 2


@pytest.mark.asyncio
async def test_inject_recaptcha_token():
    """Test injecting reCAPTCHA token"""
    mock_page = MagicMock()
    mock_page.evaluate.return_value = None

    await inject_recaptcha_token(mock_page, "test_token_123")

    # Verify evaluate was called
    mock_page.evaluate.assert_called_once()
    call_args = str(mock_page.evaluate.call_args)
    assert "test_token_123" in call_args


@pytest.mark.asyncio
async def test_inject_hcaptcha_token():
    """Test injecting hCaptcha token"""
    mock_page = MagicMock()
    mock_page.evaluate.return_value = None

    await inject_hcaptcha_token(mock_page, "test_token_456")

    # Verify evaluate was called
    mock_page.evaluate.assert_called_once()
    call_args = str(mock_page.evaluate.call_args)
    assert "test_token_456" in call_args


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.asyncio.sleep")
async def test_verify_solution_accepted(mock_sleep):
    """Test verifying CAPTCHA solution was accepted"""
    mock_page = MagicMock()
    mock_page.query_selector.return_value = None  # No CAPTCHA elements = success

    result = await verify_solution_accepted(mock_page)

    assert result is True


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.asyncio.sleep")
async def test_verify_solution_still_present(mock_sleep):
    """Test verifying when CAPTCHA is still present"""
    mock_page = MagicMock()
    mock_page.query_selector.return_value = MagicMock()  # CAPTCHA still present

    result = await verify_solution_accepted(mock_page)

    assert result is False


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.verify_solution_accepted")
@patch("skyvern.services.captcha_service.inject_recaptcha_token")
@patch("skyvern.services.captcha_service.poll_captcha_solution")
@patch("skyvern.services.captcha_service.submit_recaptcha_v2")
@patch("skyvern.services.captcha_service.detect_captcha_from_page")
@patch("skyvern.services.captcha_service.extract_page_url")
async def test_solve_captcha_recaptcha_v2(
    mock_extract_url,
    mock_detect,
    mock_submit,
    mock_poll,
    mock_inject,
    mock_verify,
):
    """Test end-to-end reCAPTCHA v2 solving"""
    # Setup mocks
    mock_extract_url.return_value = "https://example.com"
    mock_detect.return_value = CaptchaDetectionResult(
        captcha_type=CaptchaType.RECAPTCHA_V2,
        site_key="6Le-wvkSAAAA",
    )
    mock_submit.return_value = "captcha_id_123"
    mock_poll.return_value = "solution_token_abc"
    mock_inject.return_value = None
    mock_verify.return_value = True

    mock_page = MagicMock()
    mock_scraped_page = MagicMock()

    solution = await solve_captcha(
        page=mock_page,
        scraped_page=mock_scraped_page,
        task_id="task_123",
        step_id="step_456",
        timeout=120,
    )

    assert solution.captcha_type == CaptchaType.RECAPTCHA_V2
    assert solution.token == "solution_token_abc"
    assert solution.captcha_id == "captcha_id_123"
    assert solution.solving_time_seconds is not None

    # Verify all functions were called
    mock_detect.assert_called_once()
    mock_submit.assert_called_once()
    mock_poll.assert_called_once()
    mock_inject.assert_called_once()
    mock_verify.assert_called_once()


@pytest.mark.asyncio
@patch("skyvern.services.captcha_service.verify_solution_accepted")
@patch("skyvern.services.captcha_service.inject_hcaptcha_token")
@patch("skyvern.services.captcha_service.poll_captcha_solution")
@patch("skyvern.services.captcha_service.submit_hcaptcha")
@patch("skyvern.services.captcha_service.detect_captcha_from_page")
@patch("skyvern.services.captcha_service.extract_page_url")
async def test_solve_captcha_hcaptcha(
    mock_extract_url,
    mock_detect,
    mock_submit,
    mock_poll,
    mock_inject,
    mock_verify,
):
    """Test end-to-end hCaptcha solving"""
    # Setup mocks
    mock_extract_url.return_value = "https://example.com"
    mock_detect.return_value = CaptchaDetectionResult(
        captcha_type=CaptchaType.HCAPTCHA,
        site_key="a5f74b19-1234",
    )
    mock_submit.return_value = "captcha_id_789"
    mock_poll.return_value = "solution_token_xyz"
    mock_inject.return_value = None
    mock_verify.return_value = True

    mock_page = MagicMock()
    mock_scraped_page = MagicMock()

    solution = await solve_captcha(
        page=mock_page,
        scraped_page=mock_scraped_page,
        task_id="task_123",
        step_id="step_456",
        timeout=120,
    )

    assert solution.captcha_type == CaptchaType.HCAPTCHA
    assert solution.token == "solution_token_xyz"
    assert solution.captcha_id == "captcha_id_789"
