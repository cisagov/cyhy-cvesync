"""Tests for the CVESync configuration model."""

# Third-Party Libraries
from pydantic import ValidationError
import pytest

# cisagov Libraries
from cyhy_cvesync.models.config_model import DEFAULT_CVE_URL_PATTERN, CVESync


def test_set_json_url_pattern():
    """Test setting the JSON URL pattern."""
    config = CVESync(
        db_auth_uri="mongodb://localhost:27017",
        db_name="test_db",
        json_url_pattern="https://example.gov/cve-{year}.json",
    )
    assert config.json_url_pattern == "https://example.gov/cve-{year}.json"


def test_default_json_url_pattern():
    """Test the default JSON URL pattern."""
    config = CVESync(
        db_auth_uri="mongodb://localhost:27017",
        db_name="test_db",
    )
    assert config.json_url_pattern == DEFAULT_CVE_URL_PATTERN


def test_invalid_db_auth_uri():
    """Test an invalid database authentication URI."""
    with pytest.raises(ValidationError):
        CVESync(db_auth_uri="invalid_uri", db_name="test_db")


def test_invalid_json_url_pattern():
    """Test an invalid JSON URL pattern."""
    with pytest.raises(ValidationError):
        CVESync(
            db_auth_uri="mongodb://localhost:27017",
            db_name="test_db",
            json_url="invalid_url_pattern",
        )
