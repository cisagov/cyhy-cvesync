"""Test the cve_sync module."""

# Standard Python Libraries
import asyncio
import json
import os
from unittest.mock import Mock, patch

# Third-Party Libraries
from aiohttp import ClientResponseError, ClientSession
from pymongo import AsyncMongoClient
import pytest

# cisagov Libraries
from cyhy_cvesync import (
    DEFAULT_CVE_AUTHORITATIVE_SOURCE,
    DEFAULT_CVE_URL_PATTERN,
    __version__,
)
from cyhy_cvesync.cve_sync import fetch_cve_data, process_cve_json, process_urls

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
    client = AsyncMongoClient(db_uri)
    db = client[db_name]
    server_info = await db.command("ping")
    assert server_info["ok"] == 1.0, "Direct database ping failed"


async def test_process_cve_json_invalid_format():
    """Test processing invalid CVE JSON data."""
    with pytest.raises(ValueError, match="JSON does not look like valid CVE data."):
        await process_cve_json(
            {"format": "INVALID", "vulnerabilities": []},
            DEFAULT_CVE_AUTHORITATIVE_SOURCE,
        )


async def test_process_cve_json_malformed_1():
    """Test processing malformed CVE JSON data."""
    with pytest.raises(ValueError, match="JSON does not look like valid CVE data."):
        await process_cve_json(
            {
                "format": "NVD_CVE",
                "vulnerabilities": [{"cve": {"metrics": {"INVALID": "FOOBAR"}}}],
            },
            DEFAULT_CVE_AUTHORITATIVE_SOURCE,
        )


async def test_process_cve_json_malformed_2():
    """Test processing malformed CVE JSON data."""
    with pytest.raises(ValueError, match="JSON does not look like valid CVE data."):
        await process_cve_json(
            {
                "format": "NVD_CVE",
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "TEST",
                            "metrics": {
                                "cvssMetricV30": [
                                    {"source": DEFAULT_CVE_AUTHORITATIVE_SOURCE}
                                ]
                            },
                        }
                    }
                ],
            },
            DEFAULT_CVE_AUTHORITATIVE_SOURCE,
        )


async def test_process_cve_json_no_authoritative_metrics(caplog):
    """Test processing CVE JSON data containing no authoritative CVSS metrics."""
    # Set DEBUG log level to ensure desired log message is captured
    caplog.set_level("DEBUG")
    cves_created, cves_updated = await process_cve_json(
        {
            "format": "NVD_CVE",
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "TEST",
                        "metrics": {
                            "cvssMetricV30": [{"source": "nobody@example.gov"}]
                        },
                    }
                }
            ],
        },
        DEFAULT_CVE_AUTHORITATIVE_SOURCE,
    )
    assert cves_created == 0, "Expected no CVEs to be created"
    assert cves_updated == 0, "Expected no CVEs to be updated"
    cve_sync_output = caplog.text
    assert (
        f"Skipping TEST; no preferred CVSS metrics found from authoritative source ({DEFAULT_CVE_AUTHORITATIVE_SOURCE})."
        in cve_sync_output
    )


async def test_process_cve_json_auth_source_in_v31(db_uri, db_name):
    """Test processing CVE JSON data where the authoritative CVSS metric is v3.1."""
    cve_json_v31 = {
        "format": "NVD_CVE",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "TEST-V31",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 3.1, "version": "3.1"},
                            }
                        ],
                        "cvssMetricV30": [
                            {
                                "source": "nobody@example.gov",
                                "cvssData": {"baseScore": 3.0, "version": "3.0"},
                            }
                        ],
                        "cvssMetricV2": [
                            {
                                "source": "nobody@example.gov",
                                "cvssData": {"baseScore": 2.0, "version": "2.0"},
                            }
                        ],
                    },
                }
            }
        ],
    }
    cves_created, cves_updated = await process_cve_json(
        cve_json_v31, DEFAULT_CVE_AUTHORITATIVE_SOURCE
    )
    assert cves_created == 1, "Expected 1 CVE to be created"
    assert cves_updated == 0, "Expected no CVEs to be updated"

    client = AsyncMongoClient(db_uri)
    db = client[db_name]
    cve_doc = await db.cves.find_one({"_id": "TEST-V31"})
    assert cve_doc is not None, "Expected CVE document to be found in the database"
    assert cve_doc["cvss_score"] == 3.1, "Expected CVSS score to be 3.1"
    assert cve_doc["cvss_version"] == "3.1", "Expected CVSS version to be 3.1"

    # Delete the test CVE document
    await db.cves.delete_one({"_id": "TEST-V31"})


async def test_process_cve_json_auth_source_in_v30(db_uri, db_name):
    """Test processing CVE JSON data where the authoritative CVSS metric is v3.0."""
    cve_json_v30 = {
        "format": "NVD_CVE",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "TEST-V30",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nobody@example.gov",
                                "cvssData": {"baseScore": 3.1, "version": "3.1"},
                            }
                        ],
                        "cvssMetricV30": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 3.0, "version": "3.0"},
                            }
                        ],
                        "cvssMetricV2": [
                            {
                                "source": "nobody@example.gov",
                                "cvssData": {"baseScore": 2.0, "version": "2.0"},
                            }
                        ],
                    },
                }
            }
        ],
    }
    cves_created, cves_updated = await process_cve_json(
        cve_json_v30, DEFAULT_CVE_AUTHORITATIVE_SOURCE
    )
    assert cves_created == 1, "Expected 1 CVE to be created"
    assert cves_updated == 0, "Expected no CVEs to be updated"

    client = AsyncMongoClient(db_uri)
    db = client[db_name]
    cve_doc = await db.cves.find_one({"_id": "TEST-V30"})
    assert cve_doc is not None, "Expected CVE document to be found in the database"
    assert cve_doc["cvss_score"] == 3.0, "Expected CVSS score to be 3.0"
    assert cve_doc["cvss_version"] == "3.0", "Expected CVSS version to be 3.0"

    # Delete the test CVE document
    await db.cves.delete_one({"_id": "TEST-V30"})


async def test_process_cve_json_auth_source_in_v2(db_uri, db_name):
    """Test processing CVE JSON data where the authoritative CVSS metric is v2."""
    cve_json_v2 = {
        "format": "NVD_CVE",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "TEST-V2",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nobody@example.gov",
                                "cvssData": {"baseScore": 3.1, "version": "3.1"},
                            }
                        ],
                        "cvssMetricV30": [
                            {
                                "source": "nobody@example.gov",
                                "cvssData": {"baseScore": 3.0, "version": "3.0"},
                            }
                        ],
                        "cvssMetricV2": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 2.0, "version": "2.0"},
                            }
                        ],
                    },
                }
            }
        ],
    }
    cves_created, cves_updated = await process_cve_json(
        cve_json_v2, DEFAULT_CVE_AUTHORITATIVE_SOURCE
    )
    assert cves_created == 1, "Expected 1 CVE to be created"
    assert cves_updated == 0, "Expected no CVEs to be updated"

    client = AsyncMongoClient(db_uri)
    db = client[db_name]
    cve_doc = await db.cves.find_one({"_id": "TEST-V2"})
    assert cve_doc is not None, "Expected CVE document to be found in the database"
    assert cve_doc["cvss_score"] == 2.0, "Expected CVSS score to be 2.0"
    assert cve_doc["cvss_version"] == "2.0", "Expected CVSS version to be 2.0"

    # Delete the test CVE document
    await db.cves.delete_one({"_id": "TEST-V2"})


async def test_process_cve_json_multiple_auth_metrics(db_uri, db_name):
    """Test processing CVE JSON data with multiple authoritative CVSS metrics."""
    cve_json = {
        "format": "NVD_CVE",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "TEST-MULTI-AUTH",
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 2.0, "version": "2.0"},
                            }
                        ],
                        "cvssMetricV30": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 3.0, "version": "3.0"},
                            }
                        ],
                        "cvssMetricV31": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 3.1, "version": "3.1"},
                            }
                        ],
                    },
                }
            }
        ],
    }
    cves_created, cves_updated = await process_cve_json(
        cve_json, DEFAULT_CVE_AUTHORITATIVE_SOURCE
    )
    assert cves_created == 1, "Expected 1 CVE to be created"
    assert cves_updated == 0, "Expected no CVEs to be updated"

    client = AsyncMongoClient(db_uri)
    db = client[db_name]
    cve_doc = await db.cves.find_one({"_id": "TEST-MULTI-AUTH"})
    assert cve_doc is not None, "Expected CVE document to be found in the database"
    assert cve_doc["cvss_score"] == 3.1, "Expected CVSS score to be 3.1"
    assert cve_doc["cvss_version"] == "3.1", "Expected CVSS version to be 3.1"

    # Delete the test CVE document
    await db.cves.delete_one({"_id": "TEST-MULTI-AUTH"})


async def test_process_cve_json_empty_id():
    """Test processing CVE JSON data with an empty CVE ID."""
    cve_json_empty_id = {
        "format": "NVD_CVE",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "",
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "version": "3.1"}}
                        ]
                    },
                }
            }
        ],
    }
    with pytest.raises(ValueError, match="CVE ID is empty."):
        await process_cve_json(cve_json_empty_id, DEFAULT_CVE_AUTHORITATIVE_SOURCE)


async def test_fetch_cve_data_invalid_url_scheme():
    """Test fetching CVE data with an invalid URL scheme."""
    cve_json_url = "ftp://example.com/cve.json"

    with pytest.raises(ValueError, match="Invalid URL scheme in CVE JSON URL: ftp"):
        async with ClientSession() as session:
            await fetch_cve_data(session, cve_json_url, gzipped=False)


@patch("aiohttp.client.ClientSession.get")
async def test_fetch_cve_data_json_decode_error(mock_get):
    """Test fetching CVE data with a JSON decode error."""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = asyncio.Future()
    mock_response.read.return_value.set_result(b"Invalid JSON")
    mock_get.return_value.__aenter__.return_value = mock_response

    with pytest.raises(json.JSONDecodeError):
        async with ClientSession() as session:
            await fetch_cve_data(session, "https://example.com/cve.json", gzipped=False)


@patch("aiohttp.client.ClientSession.get")
async def test_fetch_cve_data_non_200_response(mock_urlopen):
    """Test fetching CVE data with a non-200 HTTP response."""
    mock_response = Mock()
    mock_response.status = 500
    mock_urlopen.return_value.__aenter__.return_value = mock_response

    with pytest.raises(ClientResponseError, match="Failed to retrieve CVE data."):
        async with ClientSession() as session:
            await fetch_cve_data(session, "https://example.com/cve.json", gzipped=False)


@patch("aiohttp.client.ClientSession.get")
async def test_fetch_cve_data_empty_response(mock_urlopen):
    """Test fetching CVE data with an empty HTTP response."""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.read.return_value = asyncio.Future()
    mock_response.read.return_value.set_result(b"")
    mock_urlopen.return_value.__aenter__.return_value = mock_response

    with pytest.raises(ValueError, match="Empty response received from the server."):
        async with ClientSession() as session:
            await fetch_cve_data(session, "https://example.com/cve.json", gzipped=False)


async def test_fetch_real_cve_data():
    """Test fetching CVE data."""
    cve_url = DEFAULT_CVE_URL_PATTERN.format(year=2024)
    async with ClientSession() as session:
        cve_json = await fetch_cve_data(session, cve_url, gzipped=True)
    assert "vulnerabilities" in cve_json, "Expected 'vulnerabilities' in CVE data"
    assert (
        len(cve_json["vulnerabilities"]) > 0
    ), "Expected at least one CVE item in CVE data"


async def test_process_urls_create_cves():
    """Test processing URLs where new CVEs are created."""
    cve_json_data = {
        "format": "NVD_CVE",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-TEST-1",
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 9.8, "version": "2.0"},
                            }
                        ]
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-TEST-2",
                    "metrics": {
                        "cvssMetricV30": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 8.5, "version": "3.0"},
                            }
                        ]
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-TEST-3",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 4.0, "version": "3.1"},
                            }
                        ]
                    },
                }
            },
        ],
    }
    with patch("cyhy_cvesync.cve_sync.fetch_cve_data", return_value=cve_json_data):
        created, updated, deleted = await process_urls(
            ["https://example.com/cve.json"],
            cve_data_gzipped=False,
            concurrency=1,
            cve_authoritative_source=DEFAULT_CVE_AUTHORITATIVE_SOURCE,
        )
        assert created == 3, "Expected 3 CVEs to be created"
        assert updated == 0, "Expected no CVEs to be updated"
        assert deleted == 0, "Expected no CVEs to be deleted"


async def test_process_urls_update_cves():
    """Test processing URLs where CVEs are updated."""
    cve_json_data = {
        "format": "NVD_CVE",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-TEST-1",
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 9.1, "version": "2.0"},
                            }
                        ]
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-TEST-2",
                    "metrics": {
                        "cvssMetricV30": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 8.5, "version": "3.0"},
                            }
                        ]
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-TEST-3",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 7.2, "version": "3.1"},
                            }
                        ]
                    },
                }
            },
        ],
    }
    with patch("cyhy_cvesync.cve_sync.fetch_cve_data", return_value=cve_json_data):
        created, updated, deleted = await process_urls(
            ["https://example.com/cve.json"],
            cve_data_gzipped=False,
            concurrency=1,
            cve_authoritative_source=DEFAULT_CVE_AUTHORITATIVE_SOURCE,
        )
        assert created == 0, "Expected no CVEs to be created"
        assert updated == 2, "Expected 2 CVEs to be updated"
        assert deleted == 0, "Expected no CVEs to be deleted"


async def test_process_urls_delete_cves():
    """Test processing URLs where CVEs are deleted."""
    cve_json_data = {
        "format": "NVD_CVE",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-TEST-1",
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 9.1, "version": "2.0"},
                            }
                        ]
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-TEST-3",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 7.2, "version": "3.1"},
                            }
                        ]
                    },
                }
            },
        ],
    }
    with patch("cyhy_cvesync.cve_sync.fetch_cve_data", return_value=cve_json_data):
        created, updated, deleted = await process_urls(
            ["https://example.com/cve.json"],
            cve_data_gzipped=False,
            concurrency=1,
            cve_authoritative_source=DEFAULT_CVE_AUTHORITATIVE_SOURCE,
        )
        assert created == 0, "Expected no CVEs to be created"
        assert updated == 0, "Expected no CVEs to be updated"
        assert deleted == 1, "Expected 1 CVE to be deleted"


async def test_process_urls_create_update_delete_cves():
    """Test processing URLs where CVEs are created, updated, and deleted."""
    cve_json_data = {
        "format": "NVD_CVE",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-TEST-1",
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 9.3, "version": "2.0"},
                            }
                        ]
                    },
                }
            },
            {
                "cve": {
                    "id": "CVE-TEST-4",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": DEFAULT_CVE_AUTHORITATIVE_SOURCE,
                                "cvssData": {"baseScore": 5.5, "version": "3.1"},
                            }
                        ]
                    },
                }
            },
        ],
    }
    with patch("cyhy_cvesync.cve_sync.fetch_cve_data", return_value=cve_json_data):
        created, updated, deleted = await process_urls(
            ["https://example.com/cve.json"],
            cve_data_gzipped=False,
            concurrency=1,
            cve_authoritative_source=DEFAULT_CVE_AUTHORITATIVE_SOURCE,
        )
        assert created == 1, "Expected 1 CVE to be created"
        assert updated == 1, "Expected 1 CVE to be updated"
        assert deleted == 1, "Expected 1 CVE to be deleted"
