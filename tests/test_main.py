"""Test the main module."""

# Standard Python Libraries
import argparse
import logging
import sys
from unittest.mock import AsyncMock, mock_open, patch

# Third-Party Libraries
from cyhy_db.models import CVEDoc
from cyhy_logging import CYHY_ROOT_LOGGER
import pytest

# cisagov Libraries
from cyhy_nvdsync.main import do_nvd_sync, generate_urls, main_async
from cyhy_nvdsync.models.config_model import (
    DEFAULT_NVD_URL_PATTERN,
    NVDSync,
    NVDSyncConfig,
)

# Sample data
VALID_CVE_JSON = {
    "CVE_data_type": "CVE",
    "CVE_data_format": "MITRE",
    "CVE_data_version": "4.0",
    "CVE_data_numberOfCVEs": "24768",
    "CVE_data_timestamp": "2024-10-18T07:00Z",
    "CVE_Items": [
        {
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": "4.0",
                "CVE_data_meta": {
                    "ID": "CVE-2024-0001",
                    "ASSIGNER": "psirt@purestorage.com",
                },
                "problemtype": {
                    "problemtype_data": [
                        {"description": [{"lang": "en", "value": "CWE-1188"}]}
                    ]
                },
                "references": {
                    "reference_data": [
                        {
                            "url": "https://purestorage.com/security",
                            "name": "https://purestorage.com/security",
                            "refsource": "",
                            "tags": ["Vendor Advisory"],
                        }
                    ]
                },
                "description": {
                    "description_data": [
                        {
                            "lang": "en",
                            "value": "A condition exists in FlashArray Purity whereby a local account intended for initial array configuration remains active potentially allowing a malicious actor to gain elevated privileges.",
                        }
                    ]
                },
            },
            "configurations": {
                "CVE_data_version": "4.0",
                "nodes": [
                    {
                        "operator": "OR",
                        "children": [],
                        "cpe_match": [
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "6.4.0",
                                "versionEndIncluding": "6.4.10",
                                "cpe_name": [],
                            },
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "6.3.0",
                                "versionEndIncluding": "6.3.14",
                                "cpe_name": [],
                            },
                        ],
                    }
                ],
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9,
                }
            },
            "publishedDate": "2024-09-23T18:15Z",
            "lastModifiedDate": "2024-09-27T14:08Z",
        },
        {
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": "4.0",
                "CVE_data_meta": {
                    "ID": "CVE-2024-0002",
                    "ASSIGNER": "psirt@purestorage.com",
                },
                "problemtype": {
                    "problemtype_data": [
                        {"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]}
                    ]
                },
                "references": {
                    "reference_data": [
                        {
                            "url": "https://purestorage.com/security",
                            "name": "https://purestorage.com/security",
                            "refsource": "",
                            "tags": ["Vendor Advisory"],
                        }
                    ]
                },
                "description": {
                    "description_data": [
                        {
                            "lang": "en",
                            "value": "A condition exists in FlashArray Purity whereby an attacker can employ a privileged account allowing remote access to the array.",
                        }
                    ]
                },
            },
            "configurations": {
                "CVE_data_version": "4.0",
                "nodes": [
                    {
                        "operator": "OR",
                        "children": [],
                        "cpe_match": [
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "6.4.0",
                                "versionEndIncluding": "6.4.10",
                                "cpe_name": [],
                            },
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "6.3.0",
                                "versionEndIncluding": "6.3.14",
                                "cpe_name": [],
                            },
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:purestorage:purity\\/\\/fa:6.5.0:*:*:*:*:*:*:*",
                                "cpe_name": [],
                            },
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "6.2.0",
                                "versionEndIncluding": "6.2.17",
                                "cpe_name": [],
                            },
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "6.1.8",
                                "versionEndIncluding": "6.1.25",
                                "cpe_name": [],
                            },
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "6.0.7",
                                "versionEndIncluding": "6.0.9",
                                "cpe_name": [],
                            },
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "5.3.17",
                                "versionEndIncluding": "5.3.21",
                                "cpe_name": [],
                            },
                        ],
                    }
                ],
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9,
                }
            },
            "publishedDate": "2024-09-23T18:15Z",
            "lastModifiedDate": "2024-09-27T14:13Z",
        },
    ],
}


async def test_main_async_no_args():
    """Test the main_async function with no arguments."""
    test_args = ["program"]
    with patch.object(sys, "argv", test_args), patch(
        "cyhy_nvdsync.main.do_nvd_sync", new=AsyncMock()
    ) as mock_do_nvd_sync, patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(config_file=None, log_level="info"),
    ), patch(
        "logging.shutdown"
    ) as mock_logging_shutdown:

        await main_async()

        mock_do_nvd_sync.assert_called_once_with(None, "info")
        mock_logging_shutdown.assert_called_once()


async def test_main_async_with_args():
    """Test the main_async function with arguments."""
    test_args = ["program", "--config-file", "test_config.yaml", "--log-level", "debug"]
    with patch.object(sys, "argv", test_args), patch(
        "cyhy_nvdsync.main.do_nvd_sync", new=AsyncMock()
    ) as mock_do_nvd_sync, patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(
            config_file="test_config.yaml", log_level="debug"
        ),
    ), patch(
        "logging.shutdown"
    ) as mock_logging_shutdown:

        await main_async()

        mock_do_nvd_sync.assert_called_once_with("test_config.yaml", "debug")
        mock_logging_shutdown.assert_called_once()


def test_generate_urls():
    """Test the generate_urls function."""
    test_first_year = 2002
    test_current_year = 2024
    url_pattern = "https://example.com/nvd/{year}.json"
    expected_urls = [
        f"https://example.com/nvd/{year}.json"
        for year in range(test_first_year, test_current_year + 1)
    ]

    with patch("cyhy_nvdsync.main.utcnow") as mock_utcnow:
        mock_utcnow.return_value.year = test_current_year
        urls = generate_urls(url_pattern)
        assert urls == expected_urls


async def test_do_nvd_sync_fast(capfd, db_uri, db_name):
    """Test the do_nvd_sync function with a small amount of test CVE data."""
    valid_config = NVDSyncConfig(
        nvdsync=NVDSync(
            db_auth_uri=db_uri,
            db_name=db_name,
            json_url_pattern=DEFAULT_NVD_URL_PATTERN,
            log_level="info",
        )
    )
    with patch("cyhy_nvdsync.main.get_config", return_value=valid_config):
        single_cve_url = [DEFAULT_NVD_URL_PATTERN.format(year=2002)]
        with patch("cyhy_nvdsync.main.generate_urls", return_value=single_cve_url):
            with patch(
                "cyhy_nvdsync.nvd_sync.fetch_cve_data",
                return_value=VALID_CVE_JSON,
            ):
                await do_nvd_sync(config_file=None, arg_log_level=None)
    nvd_sync_output = capfd.readouterr().out
    assert "Processing CVE feed" in nvd_sync_output
    assert "NVD synchronization complete" in nvd_sync_output
    assert await CVEDoc.count() == 2
    assert await CVEDoc.get("CVE-2024-0001") is not None
    assert await CVEDoc.get("CVE-2024-0002") is not None


@pytest.mark.slow
async def test_do_nvd_sync_valid_config(capfd, db_uri, db_name):
    """Test the do_nvd_sync function with a valid configuration."""
    valid_config = NVDSyncConfig(
        nvdsync=NVDSync(
            db_auth_uri=db_uri,
            db_name=db_name,
            json_url_pattern=DEFAULT_NVD_URL_PATTERN,
            log_level="info",
        )
    )
    with patch("cyhy_nvdsync.main.get_config", return_value=valid_config):
        await do_nvd_sync(config_file=None, arg_log_level=None)
    nvd_sync_output = capfd.readouterr().out
    assert "Processing CVE feed" in nvd_sync_output
    assert "NVD synchronization complete" in nvd_sync_output


@pytest.mark.slow
async def test_do_nvd_sync_setup_logging(db_uri, db_name):
    """Test that do_nvd_sync ignores the log_level in the config if it's set via arg_log_level."""
    valid_config = NVDSyncConfig(
        nvdsync=NVDSync(
            db_auth_uri=db_uri,
            db_name=db_name,
            json_url=DEFAULT_NVD_URL_PATTERN,
            log_level="info",
        )
    )
    with patch("cyhy_nvdsync.main.get_config", return_value=valid_config):
        await do_nvd_sync(config_file=None, arg_log_level="critical")
    assert (
        logging.getLogger(f"{CYHY_ROOT_LOGGER}.main").getEffectiveLevel()
        == logging.CRITICAL
    )


async def test_do_nvd_sync_invalid_config(capfd):
    """Test the do_nvd_sync function with an invalid configuration file."""
    invalid_config = b'foo = "bar"'
    with patch("pathlib.Path.exists", return_value=True):
        with patch("os.path.isfile", return_value=True):
            with patch("builtins.open", mock_open(read_data=invalid_config)):
                with pytest.raises(SystemExit) as exc_info:
                    await do_nvd_sync(config_file="mock_file", arg_log_level="debug")
                assert "validation error for NVDSyncConfig" in capfd.readouterr().out
                assert exc_info.value.code == 1, "Expected exit code 1"


async def test_do_nvd_sync_file_not_found(capfd):
    """Test the do_nvd_sync function with a missing configuration file."""
    with pytest.raises(SystemExit) as exc_info:
        await do_nvd_sync(config_file="non-existent_file", arg_log_level="debug")
    assert "No CyHy configuration file found" in capfd.readouterr().out
    assert exc_info.value.code == 1, "Expected exit code 1"
