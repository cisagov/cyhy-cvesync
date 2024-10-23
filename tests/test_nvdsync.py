"""Test database connection."""

# Standard Python Libraries
import json
import os
from unittest.mock import Mock, patch

# Third-Party Libraries
from motor.motor_asyncio import AsyncIOMotorClient
import pytest

# cisagov Libraries
from cyhy_db.models import CVEDoc
from cyhy_nvdsync import DEFAULT_NVD_URL_PATTERN, __version__
from cyhy_nvdsync.nvd_sync import fetch_cve_data, process_cve_json, process_urls

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


async def test_process_cve_json_invalid_cve_data_type():
    """Test processing invalid CVE JSON data."""
    with pytest.raises(ValueError, match="JSON does not look like valid NVD CVE data."):
        await process_cve_json({"CVE_data_type": "INVALID", "CVE_Items": []})


async def test_process_cve_json_malformed_1():
    """Test processing malformed CVE JSON data."""
    with pytest.raises(ValueError, match="JSON does not look like valid NVD CVE data."):
        await process_cve_json(
            {
                "CVE_data_type": "CVE",
                "CVE_Items": [{"cve": {"CVE_data_meta": {"INVALID": "FOOBAR"}}}],
            }
        )


async def test_process_cve_json_malformed_2():
    """Test processing malformed CVE JSON data."""
    with pytest.raises(ValueError, match="JSON does not look like valid NVD CVE data."):
        await process_cve_json(
            {
                "CVE_data_type": "CVE",
                "CVE_Items": [
                    {
                        "cve": {"CVE_data_meta": {"ID": "TEST"}},
                        "impact": {"baseMetricV3": {"cvssV3": {}}},
                    }
                ],
            }
        )


async def test_process_cve_json_empty_id():
    """Test processing CVE JSON data with an empty CVE ID."""
    cve_json_empty_id = {
        "CVE_data_type": "CVE",
        "CVE_Items": [
            {
                "cve": {"CVE_data_meta": {"ID": ""}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 9.8, "version": "3.1"}}
                },
            }
        ],
    }
    with pytest.raises(ValueError, match="CVE ID is empty."):
        await process_cve_json(cve_json_empty_id)


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


async def test_process_urls_create_cves():
    """Test processing URLs where new CVEs are created."""
    # Delete any CVEs previously created in the test DB
    await CVEDoc.delete_all()

    cve_json_data = {
        "CVE_data_type": "CVE",
        "CVE_Items": [
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-1"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 9.8, "version": "3.1"}}
                },
            },
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-2"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 8.5, "version": "3.1"}}
                },
            },
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-3"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 4.0, "version": "3.1"}}
                },
            },
        ],
    }
    with patch("cyhy_nvdsync.nvd_sync.fetch_cve_data", return_value=cve_json_data):
        created, updated, deleted = await process_urls(
            ["https://example.com/cve.json"], cve_data_gzipped=False
        )
        assert created == 3, "Expected 3 CVEs to be created"
        assert updated == 0, "Expected no CVEs to be updated"
        assert deleted == 0, "Expected no CVEs to be deleted"


async def test_process_urls_update_cves():
    """Test processing URLs where CVEs are updated."""
    cve_json_data = {
        "CVE_data_type": "CVE",
        "CVE_Items": [
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-1"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 9.1, "version": "3.1"}}
                },
            },
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-2"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 8.5, "version": "3.1"}}
                },
            },
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-3"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 7.2, "version": "3.1"}}
                },
            },
        ],
    }
    with patch("cyhy_nvdsync.nvd_sync.fetch_cve_data", return_value=cve_json_data):
        created, updated, deleted = await process_urls(
            ["https://example.com/cve.json"], cve_data_gzipped=False
        )
        assert created == 0, "Expected no CVEs to be created"
        assert updated == 2, "Expected 2 CVEs to be updated"
        assert deleted == 0, "Expected no CVEs to be deleted"


async def test_process_urls_delete_cves():
    """Test processing URLs where CVEs are deleted."""
    cve_json_data = {
        "CVE_data_type": "CVE",
        "CVE_Items": [
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-1"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 9.1, "version": "3.1"}}
                },
            },
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-3"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 7.2, "version": "3.1"}}
                },
            },
        ],
    }
    with patch("cyhy_nvdsync.nvd_sync.fetch_cve_data", return_value=cve_json_data):
        created, updated, deleted = await process_urls(
            ["https://example.com/cve.json"], cve_data_gzipped=False
        )
        assert created == 0, "Expected no CVEs to be created"
        assert updated == 0, "Expected no CVEs to be updated"
        assert deleted == 1, "Expected 1 CVE to be deleted"


async def test_process_urls_create_update_delete_cves():
    """Test processing URLs where CVEs are created, updated, and deleted."""
    cve_json_data = {
        "CVE_data_type": "CVE",
        "CVE_Items": [
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-1"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 9.3, "version": "3.1"}}
                },
            },
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-TEST-4"}},
                "impact": {
                    "baseMetricV3": {"cvssV3": {"baseScore": 5.5, "version": "3.1"}}
                },
            },
        ],
    }
    with patch("cyhy_nvdsync.nvd_sync.fetch_cve_data", return_value=cve_json_data):
        created, updated, deleted = await process_urls(
            ["https://example.com/cve.json"], cve_data_gzipped=False
        )
        assert created == 1, "Expected 1 CVE to be created"
        assert updated == 1, "Expected 1 CVE to be updated"
        assert deleted == 1, "Expected 1 CVE to be deleted"
