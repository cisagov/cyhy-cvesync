"""This module provides functions for fetching, validating, and synchronizing Known Exploited Vulnerabilities (KEV) data."""

# Standard Python Libraries
import gzip
from io import BytesIO
import json
import logging
from typing import Dict, List, Tuple
import urllib.request

# Third-Party Libraries
from cyhy_logging import CYHY_ROOT_LOGGER
from rich.progress import track

# cisagov Libraries
from cyhy_db.models import CVEDoc

ALLOWED_URL_SCHEMES = ["http", "https"]
CVE_URL_RETRY_WAIT_SEC = 5
MAX_CVE_URL_RETRIES = 10

# Map to track existing CVE documents that were not updated
cve_map: Dict[str, CVEDoc] = {}

logger = logging.getLogger(f"{CYHY_ROOT_LOGGER}.{__name__}")


async def process_cve_json(cve_json: dict) -> Tuple[int, int]:
    """Process the provided CVEs JSON and update the database with their contents."""
    created_cve_docs_count = 0
    updated_cve_docs_count = 0

    if cve_json.get("CVE_data_type") != "CVE":
        raise ValueError("JSON does not look like valid NVD CVE data.")

    for cve in track(
        cve_json.get("CVE_Items", []),
        description="Processing CVE feed",
    ):
        try:
            cve_id = cve["cve"]["CVE_data_meta"]["ID"]
        except KeyError:
            # JSON might be malformed, so we'll log what the CVE object looks like
            # and then raise an error
            logger.error("CVE object: %s", cve)
            raise ValueError("JSON does not look like valid NVD CVE data.")
        # All fields are there but "ID" field is empty
        if not cve_id:
            raise ValueError("CVE ID is empty.")

        # Only process CVEs that have CVSS V2 or V3 data
        if any(k in cve["impact"] for k in ["baseMetricV2", "baseMetricV3"]):
            # Check if the CVE document already exists in the database
            global cve_map
            cve_doc = cve_map.pop(cve_id, None)

            version = "V3" if "baseMetricV3" in cve["impact"] else "V2"
            try:
                cvss_base_score = cve["impact"]["baseMetric" + version][
                    "cvss" + version
                ]["baseScore"]
                cvss_version_temp = cve["impact"]["baseMetric" + version][
                    "cvss" + version
                ]["version"]
            except KeyError:
                logger.error("CVE object: %s", cve)
                raise ValueError("JSON does not look like valid NVD CVE data.")

            if cve_doc:  # Update existing CVE doc
                if (
                    cve_doc.cvss_score != cvss_base_score
                    or cve_doc.cvss_version != cvss_version_temp
                ):
                    cve_doc.cvss_score = cvss_base_score
                    cve_doc.cvss_version = cvss_version_temp
                    await cve_doc.save()
                    logger.info("Updated CVE document with id: %s", cve_id)
                    updated_cve_docs_count += 1
            else:  # Create new CVE doc
                cve_doc = CVEDoc(
                    id=cve_id,
                    cvss_score=float(cvss_base_score),
                    cvss_version=cvss_version_temp,
                    severity=None,
                )
                await cve_doc.save()
                logger.info("Created CVE document with id: %s", cve_id)
                created_cve_docs_count += 1

    return created_cve_docs_count, updated_cve_docs_count


def fetch_cve_data(cve_url: str, gzipped: bool) -> dict:
    """
    Fetch the CVE data from the given URL.

    This function retrieves Common Vulnerabilities and Exposures (CVE) JSON data from the specified URL.

    Args:
        cve_url (str): The URL to fetch the CVE JSON data from.
        gzipped (bool): Whether the data is gzipped.

    Returns:
        dict: The CVE JSON data.

    Raises:
        urllib.error.HTTPError: If the CVE JSON cannot be retrieved.
        ValueError: If the URL scheme is not allowed or if no data is received from the CVE URL.
    """
    # Create a Request object so we can test the safety of the URL
    cve_request = urllib.request.Request(cve_url)
    if cve_request.type not in ALLOWED_URL_SCHEMES:
        raise ValueError("Invalid URL scheme in CVE JSON URL: %s" % cve_request.type)

    # Below we disable the bandit blacklist for the urllib.request.urlopen() function
    # since we are checking the URL scheme before using.

    with urllib.request.urlopen(cve_url) as response:  # nosec B310
        if response.status != 200:
            raise urllib.error.HTTPError(
                cve_url,
                response.status,
                "Failed to retrieve CVE data.",
                response.headers,
                None,
            )

        # Read the response content
        response_content = response.read()
        if not response_content:
            raise ValueError("Empty response received from the server.")

    if gzipped:
        # Unzip the response content and return the JSON data
        with gzip.GzipFile(fileobj=BytesIO(response_content)) as f:
            return json.loads(f.read().decode("utf-8"))
    else:
        return json.loads(response_content)


async def process_urls(
    cve_urls: List[str],
    cve_data_gzipped: bool,
) -> Tuple[int, int, int]:
    """Process URLs containing CVE data."""
    created_cve_docs_count = 0
    deleted_cve_docs_count = 0
    updated_cve_docs_count = 0

    # Fetch all existing CVE documents from the database
    global cve_map
    cve_map = {str(cve.id): cve for cve in await CVEDoc.find_all().to_list()}

    for cve_url in cve_urls:
        logging.info("Processing URL: %s", cve_url)

        cve_json = fetch_cve_data(cve_url, cve_data_gzipped)

        # Process the CVE JSON data and update the database
        created_count, updated_count = await process_cve_json(cve_json)
        created_cve_docs_count += created_count
        updated_cve_docs_count += updated_count

    # Delete any previously-existing CVE documents that were not seen while
    # processing the URLs
    for cve_doc in track(cve_map.values(), description="Deleting outdated CVE docs"):
        await cve_doc.delete()
        logger.info("Deleted outdated CVE document with id: %s", cve_doc.id)
        deleted_cve_docs_count += 1

    # If all is well, return the counts
    return created_cve_docs_count, updated_cve_docs_count, deleted_cve_docs_count
