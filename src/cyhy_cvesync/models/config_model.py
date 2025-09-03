"""Model definitions for the configuration."""

# Standard Python Libraries
from typing import Optional

# Third-Party Libraries
from pydantic import BaseModel, ConfigDict, Field

from .. import DEFAULT_CVE_AUTHORITATIVE_SOURCE, DEFAULT_CVE_URL_PATTERN


class CVESync(BaseModel):
    """Definition of a CVE Sync configuration."""

    model_config = ConfigDict(extra="forbid")

    cve_authoritative_source: str = Field(
        default=DEFAULT_CVE_AUTHORITATIVE_SOURCE,
        description="The authoritative source for CVE data",
    )
    db_auth_uri: str = Field(
        pattern=r"^mongodb://", description="MongoDB connection URI"
    )
    db_name: str = Field(description="MongoDB database name")
    json_url_gzipped: bool = Field(
        default=True,
        description="Whether the CVE JSON files are gzipped",
    )
    json_url_pattern: str = Field(
        pattern=r"^https?://",
        default=DEFAULT_CVE_URL_PATTERN,
        description="URL pattern for the CVE JSON file; note that {year} in the pattern will be substituted with each valid year",
    )
    log_level: Optional[str] = Field(
        None,
        description="Logging level",
    )
    url_concurrency: int = Field(
        default=10,
        description="Number of concurrent URL requests to fetch and process CVE data",
    )


class CVESyncConfig(BaseModel):
    """Definition of the CVESync configuration root."""

    model_config = ConfigDict(extra="ignore")

    cvesync: CVESync
