"""Model definitions for the configuration."""

# Standard Python Libraries
from typing import Optional

# Third-Party Libraries
from pydantic import BaseModel, ConfigDict, Field

from .. import DEFAULT_NVD_URL_PATTERN


class NVDSync(BaseModel):
    """Definition of a NVD Sync configuration."""

    model_config = ConfigDict(extra="forbid")

    db_auth_uri: str = Field(
        pattern=r"^mongodb://", description="MongoDB connection URI"
    )
    db_name: str = Field(description="MongoDB database name")
    json_url_gzipped: bool = Field(
        default=True,
        description="Whether the NVD JSON files are gzipped",
    )
    json_url_pattern: str = Field(
        pattern=r"^https?://",
        default=DEFAULT_NVD_URL_PATTERN,
        description="URL pattern for the NVD JSON file; note that {year} in the pattern will be substituted with each valid year",
    )
    log_level: Optional[str] = Field(
        None,
        description="Logging level",
    )


class NVDSyncConfig(BaseModel):
    """Definition of the NVDSync configuration root."""

    model_config = ConfigDict(extra="ignore")

    nvdsync: NVDSync
