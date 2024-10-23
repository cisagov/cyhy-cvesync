"""Test database connection."""

# Standard Python Libraries
import json
import os
from unittest.mock import Mock, patch

# Third-Party Libraries
from motor.motor_asyncio import AsyncIOMotorClient
import pytest

# cisagov Libraries
from cyhy_nvdsync import DEFAULT_NVD_URL_PATTERN, __version__
from cyhy_nvdsync.nvd_sync import fetch_cve_data

# define sources of version strings
RELEASE_TAG = os.getenv("RELEASE_TAG")
PROJECT_VERSION = __version__


@pytest.mark.skipif(
    RELEASE_TAG in [None, ""], reason="this is not a release (RELEASE_TAG not set)"
)
def test_release_version():
    """Verify that release tag version agrees with the module version."""
    assert (
        RELEASE_TAG == f"v{PROJECT_VERSION}"
    ), "RELEASE_TAG does not match the project version"


async def test_connection_motor(db_uri, db_name):
    """Test the database connection."""
    client = AsyncIOMotorClient(db_uri)
    db = client[db_name]
    server_info = await db.command("ping")
    assert server_info["ok"] == 1.0, "Direct database ping failed"


@patch("urllib.request.urlopen")
def test_fetch_cve_data_invalid_url_scheme(mock_urlopen):
    """Test fetching CVE data with an invalid URL scheme."""
    cve_json_url = "ftp://example.com/nvd.json"

    with pytest.raises(ValueError, match="Invalid URL scheme in CVE JSON URL: ftp"):
        fetch_cve_data(cve_json_url, gzipped=False)


@patch("urllib.request.urlopen")
def test_fetch_cve_data_json_decode_error(mock_urlopen):
    """Test fetching CVE data with a JSON decode error."""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = b"Invalid JSON"
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with pytest.raises(json.JSONDecodeError):
        fetch_cve_data("https://example.com/nvd.json", gzipped=False)


@patch("urllib.request.urlopen")
def test_fetch_cve_data_non_200_response(mock_urlopen):
    """Test fetching CVE data with a non-200 HTTP response."""
    mock_response = Mock()
    mock_response.status = 500
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with pytest.raises(Exception, match="Failed to retrieve CVE data."):
        fetch_cve_data("https://example.com/nvd.json", gzipped=False)


@patch("urllib.request.urlopen")
def test_fetch_cve_data_empty_response(mock_urlopen):
    """Test fetching CVE data with an empty HTTP response."""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = b""
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with pytest.raises(ValueError, match="Empty response received from the server."):
        fetch_cve_data("https://example.com/nvd.json", gzipped=False)


def test_fetch_real_cve_data():
    """Test fetching CVE data."""
    cve_url = DEFAULT_NVD_URL_PATTERN.format(year=2024)
    cve_json = fetch_cve_data(cve_url, gzipped=True)
    assert "CVE_Items" in cve_json, "Expected 'CVE_Items' in CVE data"
    assert len(cve_json["CVE_Items"]) > 0, "Expected at least one CVE item in CVE data"
