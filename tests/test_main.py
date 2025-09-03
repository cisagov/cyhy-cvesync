"""Test the main module."""

# Standard Python Libraries
import argparse
import asyncio
import sys
from unittest.mock import AsyncMock, mock_open, patch

# Third-Party Libraries
from aiohttp import ClientSession
import pytest

# cisagov Libraries
from cyhy_cvesync.cve_sync import fetch_cve_data
from cyhy_cvesync.main import do_cve_sync, generate_urls, main_async
from cyhy_cvesync.models.config_model import (
    DEFAULT_CVE_URL_PATTERN,
    CVESync,
    CVESyncConfig,
)
from cyhy_db.models import CVEDoc


async def fetch_sample_cve_data(year):
    """Fetch sample CVE data from the default CVE URL."""
    async with ClientSession() as session:
        return await fetch_cve_data(
            session, DEFAULT_CVE_URL_PATTERN.format(year=year), gzipped=True
        )


# Download sample CVE data for a single year from the default CVE URL
SAMPLE_CVE_JSON = asyncio.run(fetch_sample_cve_data(2024))

# Create a smaller sample dictionary that includes a target number of CVEs that
# meet our criteria
SAMPLE_CVE_JSON_SMALL_VALID_CVES = 20
count = 0
hits = 0
for cve in SAMPLE_CVE_JSON["vulnerabilities"]:
    count += 1
    metrics = cve.get("cve", {}).get("metrics", {}).keys()
    if metrics & {"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}:
        hits += 1
    if hits == SAMPLE_CVE_JSON_SMALL_VALID_CVES:
        break
SAMPLE_CVE_JSON_SMALL = SAMPLE_CVE_JSON.copy()
SAMPLE_CVE_JSON_SMALL["vulnerabilities"] = SAMPLE_CVE_JSON["vulnerabilities"][:count]


async def test_main_async_no_args():
    """Test the main_async function with no arguments."""
    test_args = ["program"]
    with patch.object(sys, "argv", test_args), patch(
        "cyhy_cvesync.main.do_cve_sync", new=AsyncMock()
    ) as mock_do_cve_sync, patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(config_file=None, log_level="info"),
    ), patch(
        "logging.shutdown"
    ) as mock_logging_shutdown:

        await main_async()

        mock_do_cve_sync.assert_called_once_with(None, "info")
        mock_logging_shutdown.assert_called_once()


async def test_main_async_with_args():
    """Test the main_async function with arguments."""
    test_args = ["program", "--config-file", "test_config.yaml", "--log-level", "debug"]
    with patch.object(sys, "argv", test_args), patch(
        "cyhy_cvesync.main.do_cve_sync", new=AsyncMock()
    ) as mock_do_cve_sync, patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(
            config_file="test_config.yaml", log_level="debug"
        ),
    ), patch(
        "logging.shutdown"
    ) as mock_logging_shutdown:

        await main_async()

        mock_do_cve_sync.assert_called_once_with("test_config.yaml", "debug")
        mock_logging_shutdown.assert_called_once()


def test_generate_urls():
    """Test the generate_urls function."""
    test_first_year = 2002
    test_current_year = 2024
    url_pattern = "https://example.com/cve/{year}.json"
    expected_urls = [
        f"https://example.com/cve/{year}.json"
        for year in range(test_first_year, test_current_year + 1)
    ]

    with patch("cyhy_cvesync.main.utcnow") as mock_utcnow:
        mock_utcnow.return_value.year = test_current_year
        urls = generate_urls(url_pattern)
        assert urls == expected_urls


async def test_do_cve_sync_fast_no_arg_log_level(capfd, db_uri, db_name):
    """Test the do_cve_sync function with a small amount of test CVE data without setting the arg_log_level."""
    valid_config = CVESyncConfig(
        cvesync=CVESync(
            db_auth_uri=db_uri,
            db_name=db_name,
            json_url_pattern=DEFAULT_CVE_URL_PATTERN,
            log_level="info",
        )
    )
    with patch("cyhy_cvesync.main.get_config", return_value=valid_config):
        single_cve_url = [DEFAULT_CVE_URL_PATTERN.format(year=2024)]
        with patch("cyhy_cvesync.main.generate_urls", return_value=single_cve_url):
            with patch(
                "cyhy_cvesync.cve_sync.fetch_cve_data",
                return_value=SAMPLE_CVE_JSON_SMALL,
            ):
                await do_cve_sync(config_file=None, arg_log_level=None)
    cve_sync_output = capfd.readouterr().out
    assert "CVE synchronization complete" in cve_sync_output
    assert await CVEDoc.count() == SAMPLE_CVE_JSON_SMALL_VALID_CVES


async def test_do_cve_sync_fast_set_arg_log_level(capfd, db_uri, db_name):
    """Test the do_cve_sync function with a small amount of test CVE data when setting the arg_log_level."""
    valid_config = CVESyncConfig(
        cvesync=CVESync(
            db_auth_uri=db_uri,
            db_name=db_name,
            json_url_pattern=DEFAULT_CVE_URL_PATTERN,
            log_level="info",
        )
    )
    with patch("cyhy_cvesync.main.get_config", return_value=valid_config):
        single_cve_url = [DEFAULT_CVE_URL_PATTERN.format(year=2024)]
        with patch("cyhy_cvesync.main.generate_urls", return_value=single_cve_url):
            with patch(
                "cyhy_cvesync.cve_sync.fetch_cve_data",
                return_value=SAMPLE_CVE_JSON_SMALL,
            ):
                await do_cve_sync(config_file=None, arg_log_level="debug")
    cve_sync_output = capfd.readouterr().out
    assert "CVE synchronization complete" in cve_sync_output
    assert await CVEDoc.count() == SAMPLE_CVE_JSON_SMALL_VALID_CVES


# This test takes a long time to run since it ingests all available CVE data.
@pytest.mark.slow
async def test_do_cve_sync_valid_config(capfd, db_uri, db_name):
    """Test the do_cve_sync function with a valid configuration."""
    valid_config = CVESyncConfig(
        cvesync=CVESync(
            db_auth_uri=db_uri,
            db_name=db_name,
            json_url_pattern=DEFAULT_CVE_URL_PATTERN,
            log_level="info",
            url_concurrency=20,
        )
    )
    with patch("cyhy_cvesync.main.get_config", return_value=valid_config):
        await do_cve_sync(config_file=None, arg_log_level=None)
    cve_sync_output = capfd.readouterr().out
    assert "CVE synchronization complete" in cve_sync_output


async def test_do_cve_sync_invalid_config(capfd):
    """Test the do_cve_sync function with an invalid configuration file."""
    invalid_config = b'foo = "bar"'
    with patch("pathlib.Path.exists", return_value=True):
        with patch("os.path.isfile", return_value=True):
            with patch("builtins.open", mock_open(read_data=invalid_config)):
                with pytest.raises(SystemExit) as exc_info:
                    await do_cve_sync(config_file="mock_file", arg_log_level="debug")
                assert "validation error for CVESyncConfig" in capfd.readouterr().out
                assert exc_info.value.code == 1, "Expected exit code 1"


async def test_do_cve_sync_file_not_found(capfd):
    """Test the do_cve_sync function with a missing configuration file."""
    with pytest.raises(SystemExit) as exc_info:
        await do_cve_sync(config_file="non-existent_file", arg_log_level="debug")
    assert "No CyHy configuration file found" in capfd.readouterr().out
    assert exc_info.value.code == 1, "Expected exit code 1"
