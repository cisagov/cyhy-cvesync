"""Incomplete NVD envelopes must not be treated as empty snapshots."""

# Standard Python Libraries
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

# cisagov Libraries
from cyhy_cvesync import cve_sync

SOURCE = "nvd@nist.gov"


def existing_document(identifier="CVE-2026-1001"):
    """Provide an in-memory document at the database boundary."""
    return SimpleNamespace(
        id=identifier,
        cvss_score=4.0,
        cvss_version="3.1",
        save=AsyncMock(),
        delete=AsyncMock(),
    )


def valid_record(identifier="CVE-2026-1001"):
    """Create the fields used by the real CVE processing function."""
    return {
        "cve": {
            "id": identifier,
            "metrics": {
                "cvssMetricV31": [
                    {"source": SOURCE, "cvssData": {"baseScore": 7.5, "version": "3.1"}}
                ]
            },
        }
    }


class FeedStructureValidationTest(unittest.IsolatedAsyncioTestCase):
    """Validate input at the start of the real feed processor."""

    def setUp(self):
        """Keep each case's synchronization state independent."""
        self.original_map = cve_sync.cve_map
        self.addCleanup(setattr, cve_sync, "cve_map", self.original_map)
        self.doc = existing_document()
        cve_sync.cve_map = {self.doc.id: self.doc}

    async def test_missing_or_nonarray_vulnerabilities_raise_before_processing(self):
        """Omitted, null, or incorrectly typed lists are malformed input."""
        feeds = [{"format": "NVD_CVE"}] + [
            {"format": "NVD_CVE", "vulnerabilities": value}
            for value in [None, {}, "", False, 0, ()]
        ]
        for feed in feeds:
            with self.subTest(feed=feed):
                original = deepcopy(feed)
                with self.assertRaisesRegex(ValueError, "vulnerabilities"):
                    await cve_sync.process_cve_json(feed, SOURCE)
                self.assertEqual(feed, original)
                self.assertIs(cve_sync.cve_map[self.doc.id], self.doc)
                self.doc.save.assert_not_awaited()
                self.doc.delete.assert_not_awaited()

    async def test_nonobject_envelopes_raise_the_documented_validation_error(self):
        """JSON scalars and arrays are not NVD envelope objects."""
        for value in [None, [], "NVD_CVE", 1]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                await cve_sync.process_cve_json(value, SOURCE)

    async def run_sync(self, feed, documents):
        """Run real orchestration without HTTP requests or MongoDB access."""
        query = Mock(to_list=AsyncMock(return_value=documents))
        with (
            patch.object(cve_sync.CVEDoc, "find_all", return_value=query),
            patch.object(cve_sync, "fetch_cve_data", new=AsyncMock(return_value=feed)),
        ):
            return await cve_sync.process_urls(
                ["https://feed.example/nvd.json"], False, 1, SOURCE
            )

    async def test_missing_payload_prevents_stale_document_deletion(self):
        """A successful download with an incomplete body must abort cleanup."""
        with self.assertRaisesRegex(ValueError, "vulnerabilities"):
            await self.run_sync({"format": "NVD_CVE"}, [self.doc])
        self.doc.delete.assert_not_awaited()
        self.doc.save.assert_not_awaited()

    async def test_explicit_empty_array_preserves_existing_empty_feed_behavior(self):
        """A present empty array retains the existing authoritative semantics."""
        counts = await self.run_sync(
            {"format": "NVD_CVE", "vulnerabilities": []}, [self.doc]
        )
        self.assertEqual(counts, (0, 0, 1))
        self.doc.delete.assert_awaited_once()

    async def test_valid_feed_updates_retained_records_and_deletes_absent_ones(self):
        """Valid synchronization still uses scores and stale-record cleanup."""
        obsolete = existing_document("CVE-2026-1002")
        counts = await self.run_sync(
            {"format": "NVD_CVE", "vulnerabilities": [valid_record()]},
            [self.doc, obsolete],
        )
        self.assertEqual(counts, (0, 1, 1))
        self.assertEqual(self.doc.cvss_score, 7.5)
        self.doc.save.assert_awaited_once()
        self.doc.delete.assert_not_awaited()
        obsolete.delete.assert_awaited_once()

    async def test_wrong_format_keeps_existing_rejection(self):
        """The original format check remains in force."""
        with self.assertRaises(ValueError):
            await cve_sync.process_cve_json(
                {"format": "other", "vulnerabilities": []}, SOURCE
            )


if __name__ == "__main__":
    unittest.main()
