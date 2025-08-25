"""This module provides functions for fetching and synchronizing Common Vulnerabilities and Exposures (CVE) data."""

# Standard Python Libraries
import asyncio
import gzip
from io import BytesIO
import json
import logging
from typing import Dict, List, Tuple
import urllib.request

# Third-Party Libraries
from aiohttp import ClientResponseError, ClientSession
from cyhy_logging import CYHY_ROOT_LOGGER
from rich.progress import track

# cisagov Libraries
from cyhy_db.models import CVEDoc

ALLOWED_URL_SCHEMES = ["http", "https"]
CVE_URL_RETRY_WAIT_SEC = 5
MAX_CVE_URL_RETRIES = 10

# Map to track existing CVE documents that were not updated
cve_map: Dict[str, CVEDoc] = {}
cve_map_lock = asyncio.Lock()

logger = logging.getLogger(f"{CYHY_ROOT_LOGGER}.{__name__}")


async def process_cve_json(cve_json: dict) -> Tuple[int, int]:
    """
    Process the provided CVEs JSON and update the database with their contents.

    Args:
        cve_json (dict): The JSON data containing information about CVEs.

    Returns:
        Tuple[int, int]: A tuple containing the counts of created and updated
        CVE documents, respectively.

    Raises:
        ValueError: If the JSON CVE data is malformed or missing key fields.
    """
    created_cve_docs_count = 0
    updated_cve_docs_count = 0

    if cve_json.get("format") != "NVD_CVE":
        raise ValueError("JSON does not look like valid CVE data.")

    cve_items = cve_json.get("vulnerabilities", [])

    logger.info(
        "Async task %d: Starting to process %d CVEs",
        id(asyncio.current_task()),
        len(cve_items),
    )
    for cve in cve_items:
        try:
            cve_id = cve["cve"]["id"]
        except KeyError:
            # JSON might be malformed, so we'll log what the CVE object looks like
            # and then raise an error
            logger.error("CVE object: %s", cve)
            raise ValueError("JSON does not look like valid CVE data.")
        # All fields are there but "ID" field is empty
        if not cve_id:
            raise ValueError("CVE ID is empty.")

        # Only process CVEs that have CVSS V2 or V3 data
        if any(
            k in cve["cve"].get("metrics", {})
            for k in [
                "cvssMetricV2",
                "cvssMetricV30",
                "cvssMetricV31",
            ]
        ):
            # Check if the CVE document already exists in the database
            global cve_map
            async with cve_map_lock:
                cve_doc = cve_map.pop(cve_id, None)

            # Determine newest CVSS metrics version in the CVE data
            metrics_version = None
            for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if v in cve["cve"]["metrics"]:
                    metrics_version = v
                    break

            try:
                for metric in cve["cve"]["metrics"][metrics_version]:
                    if metric["type"] == "Primary":
                        cvss_base_score = metric["cvssData"]["baseScore"]
                        cvss_version_temp = metric["cvssData"]["version"]
                        break
                else:
                    logger.warning("Skipping %s; no Primary CVSS metric found.", cve_id)
                    continue
            except KeyError:
                logger.error("CVE object: %s", cve)
                raise ValueError("JSON does not look like valid CVE data.")

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
    logger.info(
        "Async task %d: Created %d CVE document(s), updated %d CVE document(s)",
        id(asyncio.current_task()),
        created_cve_docs_count,
        updated_cve_docs_count,
    )

    return created_cve_docs_count, updated_cve_docs_count


async def fetch_cve_data(session: ClientSession, cve_url: str, gzipped: bool) -> dict:
    """
    Fetch the CVE data from the given URL.

    This function retrieves Common Vulnerabilities and Exposures (CVE) JSON data
    from the specified URL.

    Args:
        session (ClientSession): The aiohttp client session.
        cve_url (str): The URL to fetch the CVE JSON data from.
        gzipped (bool): Whether the data is gzipped.

    Returns:
        dict: The CVE JSON data.

    Raises:
        aiohttp.ClientResponseError: If the response status is not 200.
        ValueError: If the URL scheme is not allowed or if no data is received
        from the CVE URL.
    """
    # Create a Request object so we can test the safety of the URL
    cve_request = urllib.request.Request(cve_url)
    if cve_request.type not in ALLOWED_URL_SCHEMES:
        raise ValueError("Invalid URL scheme in CVE JSON URL: %s" % cve_request.type)

    async with session.get(cve_url) as response:
        if response.status != 200:
            raise ClientResponseError(
                headers=response.headers,
                history=response.history,
                message="Failed to retrieve CVE data: %s" % response.reason,
                request_info=response.request_info,
                status=response.status,
            )

        # Read the response content
        response_content = await response.read()
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
    concurrency: int,
) -> Tuple[int, int, int]:
    """
    Process URLs containing CVE data.

    This function fetches CVE data from the provided URLs, processes the data,
    and updates the database accordingly. It also deletes any outdated CVE
    documents that were not seen during the processing of the URLs.

    Args:
        cve_urls (List[str]): A list of URLs containing CVE data.
        cve_data_gzipped (bool): A flag indicating whether the CVE data is gzipped.
        concurrency (int): The number of concurrent URL requests to make and process.

    Returns:
        Tuple[int, int, int]: A tuple containing the counts of created, updated,
        and deleted CVE documents, respectively.
    """
    created_cve_docs_count = 0
    deleted_cve_docs_count = 0
    updated_cve_docs_count = 0
    cve_docs_count_lock = asyncio.Lock()

    # Fetch all existing CVE documents from the database
    global cve_map
    cve_map = {str(cve.id): cve for cve in await CVEDoc.find_all().to_list()}

    async def process_single_url(
        semaphore: asyncio.Semaphore, session: ClientSession, cve_url: str
    ):
        nonlocal created_cve_docs_count, updated_cve_docs_count
        async with semaphore:
            logging.info("Processing URL: %s", cve_url)
            cve_json = await fetch_cve_data(session, cve_url, cve_data_gzipped)
            created_count, updated_count = await process_cve_json(cve_json)
            async with cve_docs_count_lock:
                created_cve_docs_count += created_count
                updated_cve_docs_count += updated_count

    semaphore = asyncio.Semaphore(concurrency)
    async with ClientSession() as session:
        tasks = [
            process_single_url(semaphore, session, cve_url) for cve_url in cve_urls
        ]
        await asyncio.gather(*tasks)

    # Delete any previously-existing CVE documents that were not seen while
    # processing the URLs
    for cve_doc in track(cve_map.values(), description="Deleting outdated CVE docs"):
        await cve_doc.delete()
        logger.info("Deleted outdated CVE document with id: %s", cve_doc.id)
        deleted_cve_docs_count += 1

    # If all is well, return the counts
    return created_cve_docs_count, updated_cve_docs_count, deleted_cve_docs_count
