"""Protect CVE synchronization from an empty or unusable source plan."""

# Standard Python Libraries
import asyncio
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

# cisagov Libraries
from cyhy_cvesync import cve_sync


class SyncInputValidationTest(unittest.IsolatedAsyncioTestCase):
    """Exercise the real sync orchestration with isolated database and HTTP I/O."""

    def setUp(self):
        """Install in-memory document and transport boundaries for each test."""
        self.stack = self.enterContext(ExitStack())
        self.kept = self.document("CVE-2026-10001", 5.0)
        self.obsolete = self.document("CVE-2026-10002", 3.0)
        self.model = self.stack.enter_context(patch.object(cve_sync, "CVEDoc"))
        self.model.find_all.return_value.to_list = AsyncMock(
            return_value=[self.kept, self.obsolete]
        )
        self.session = self.stack.enter_context(patch.object(cve_sync, "ClientSession"))
        self.fetch = self.stack.enter_context(
            patch.object(cve_sync, "fetch_cve_data", new_callable=AsyncMock)
        )
        self.stack.enter_context(patch.object(cve_sync, "cve_map", {}))
        self.stack.enter_context(patch.object(cve_sync, "cve_map_lock", asyncio.Lock()))
        self.fetch.return_value = self.feed(self.kept.id)

    @staticmethod
    def document(identifier, score):
        """Create a document double exposing only fields used by synchronization."""
        return SimpleNamespace(
            id=identifier,
            cvss_score=score,
            cvss_version="3.1",
            save=AsyncMock(),
            delete=AsyncMock(),
        )

    @staticmethod
    def feed(identifier):
        """Return a minimal accepted NVD response for an existing document."""
        return {
            "format": "NVD_CVE",
            "vulnerabilities": [
                {
                    "cve": {
                        "id": identifier,
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "cvssData": {"baseScore": 7.0, "version": "3.1"},
                                }
                            ]
                        },
                    }
                }
            ],
        }

    async def test_empty_urls_are_rejected_before_reading_or_deleting_documents(self):
        """An omitted source list must never mean deletion of the entire collection."""
        with self.assertRaisesRegex(ValueError, "[Aa]t least one"):
            await cve_sync.process_urls([], False, 1, "nvd@nist.gov")
        self.model.find_all.assert_not_called()
        self.session.assert_not_called()
        self.kept.delete.assert_not_awaited()
        self.obsolete.delete.assert_not_awaited()

    async def test_empty_urls_are_invalid_even_when_the_database_is_empty(self):
        """Input validity must not depend on whether documents currently exist."""
        self.model.find_all.return_value.to_list.return_value = []
        with self.assertRaisesRegex(ValueError, "[Aa]t least one"):
            await cve_sync.process_urls([], True, 2, "nvd@nist.gov")
        self.model.find_all.assert_not_called()

    async def test_nonpositive_concurrency_is_rejected_before_database_access(self):
        """Zero workers must fail promptly rather than hang with the database loaded."""
        for concurrency in (-2, -1, 0):
            with self.subTest(concurrency=concurrency):
                self.model.find_all.reset_mock()
                with self.assertRaisesRegex(ValueError, "concurrency"):
                    await asyncio.wait_for(
                        cve_sync.process_urls(
                            ["https://example.test/feed.json"],
                            False,
                            concurrency,
                            "nvd@nist.gov",
                        ),
                        timeout=1.0,
                    )
                self.model.find_all.assert_not_called()
                self.session.assert_not_called()

    async def test_valid_source_updates_seen_and_deletes_obsolete_documents(self):
        """A nonempty source plan keeps normal update and stale-record removal."""
        result = await cve_sync.process_urls(
            ["https://example.test/feed.json"], False, 1, "nvd@nist.gov"
        )
        self.assertEqual(result, (0, 1, 1))
        self.assertEqual(self.kept.cvss_score, 7.0)
        self.kept.save.assert_awaited_once()
        self.kept.delete.assert_not_awaited()
        self.obsolete.delete.assert_awaited_once()

    async def test_fetched_empty_feed_retains_existing_cleanup_semantics(self):
        """An actual empty authoritative response differs from no source URLs."""
        self.fetch.return_value = {"format": "NVD_CVE", "vulnerabilities": []}
        result = await cve_sync.process_urls(
            ["https://example.test/feed.json"], False, 1, "nvd@nist.gov"
        )
        self.assertEqual(result, (0, 0, 2))
        self.kept.delete.assert_awaited_once()
        self.obsolete.delete.assert_awaited_once()

    async def test_download_failure_does_not_delete_existing_documents(self):
        """A failed fetch must still prevent cleanup."""
        self.fetch.side_effect = ValueError("offline fixture failed")
        with self.assertRaisesRegex(ValueError, "offline fixture failed"):
            await cve_sync.process_urls(
                ["https://example.test/feed.json"], False, 1, "nvd@nist.gov"
            )
        self.kept.delete.assert_not_awaited()
        self.obsolete.delete.assert_not_awaited()

    async def test_multiple_sources_can_preserve_both_existing_documents(self):
        """Positive concurrency still handles independent feeds and counts."""
        self.fetch.side_effect = [self.feed(self.kept.id), self.feed(self.obsolete.id)]
        result = await cve_sync.process_urls(
            ["https://example.test/one.json", "https://example.test/two.json"],
            False,
            2,
            "nvd@nist.gov",
        )
        self.assertEqual(result, (0, 2, 0))
        self.kept.delete.assert_not_awaited()
        self.obsolete.delete.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
