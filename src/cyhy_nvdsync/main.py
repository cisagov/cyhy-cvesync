"""cyhy_nvdsync Python library and tool."""

# Standard Python Libraries
import argparse
import asyncio
import logging
import sys
from typing import Optional

# Third-Party Libraries
from cyhy_config import get_config
from cyhy_logging import CYHY_ROOT_LOGGER, setup_logging
from pydantic import ValidationError

# cisagov Libraries
from cyhy_db import initialize_db
from cyhy_db.utils.time import utcnow

from ._version import __version__
from .models.config_model import NVDSyncConfig
from .nvd_sync import process_urls

NVD_FIRST_YEAR = 2002

logger = logging.getLogger(f"{CYHY_ROOT_LOGGER}.{__name__}")


def generate_urls(url_pattern: str) -> list[str]:
    """Return the NVD URLs for each year."""
    current_year = utcnow().year
    years = list(range(NVD_FIRST_YEAR, current_year + 1))
    return [url_pattern.format(**{"year": year}) for year in years]


async def do_nvd_sync(
    config_file: Optional[str] = None, arg_log_level: Optional[str] = None
) -> None:
    """Perform the NVD synchronization."""
    setup_logging(arg_log_level)

    # Get the configuration
    try:
        config = get_config(file_path=config_file, model=NVDSyncConfig)
    except ValidationError:
        sys.exit(1)
    except FileNotFoundError:
        sys.exit(1)

    if not arg_log_level and config.nvdsync.log_level:
        # Update log levels from config if they were not set by an argument
        setup_logging(config.nvdsync.log_level)

    # Initialize the database
    await initialize_db(config.nvdsync.db_auth_uri, config.nvdsync.db_name)

    # Generate the list of NVD URLs containing JSON data
    nvd_urls = generate_urls(config.nvdsync.json_url_pattern)
    logger.info("URLs to synchronize:\n%s", nvd_urls)

    # Fetch the NVD URLs and put the CVE data into the database
    created_cve_docs_count, updated_cve_docs_count, deleted_cve_docs_count = (
        await process_urls(nvd_urls, config.nvdsync.json_url_gzipped)
    )

    # Log the results
    logger.info("NVD synchronization complete.")
    logger.info("Created CVE documents: %d", created_cve_docs_count)
    logger.info("Updated CVE documents: %d", updated_cve_docs_count)
    logger.info("Deleted CVE documents: %d", deleted_cve_docs_count)


async def main_async() -> None:
    """Set up logging and call the process function."""
    parser = argparse.ArgumentParser(
        description="Cyber Hygiene National Vulnerability Database (NVD) synchronization tool",
    )
    parser.add_argument(
        "--config-file",
        help="path to the configuration file",
        metavar="config-file",
        type=str,
    )
    parser.add_argument(
        "--log-level",
        "-l",
        help="set the logging level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args()

    await do_nvd_sync(args.config_file, args.log_level)

    # Stop logging and clean up
    logging.shutdown()


def main():
    """Run the main function."""
    asyncio.run(main_async())
