"""Regression tests for CLI and library logging precedence without external I/O."""

# Standard Python Libraries
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, call, patch

# Third-Party Libraries
from cyhy_config import get_config

# cisagov Libraries
from cyhy_cvesync.main import do_cve_sync, main_async


class LoggingTest(unittest.IsolatedAsyncioTestCase):
    """Exercise the real parser and TOML loader with synchronization mocked."""

    def setUp(self):
        """Create an isolated configuration and disable all remote services."""
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.config_path = Path(temporary_directory.name) / "cyhy.toml"
        self.logging = self.enterContext(patch("cyhy_cvesync.main.setup_logging"))
        self.database = self.enterContext(
            patch("cyhy_cvesync.main.initialize_db", new_callable=AsyncMock)
        )
        self.process = self.enterContext(
            patch(
                "cyhy_cvesync.main.process_urls",
                new_callable=AsyncMock,
                return_value=(0, 0, 0),
            )
        )
        self.shutdown = self.enterContext(patch("logging.shutdown"))
        # Load the real TOML file, but never attempt AWS Parameter Store lookup.
        self.enterContext(
            patch(f"{get_config.__module__}.read_config_ssm", return_value=None)
        )

    def write_config(self, level=None):
        """Write a valid local configuration, optionally including a log level."""
        text = (
            "[cvesync]\n"
            'db_auth_uri = "mongodb://localhost:27017"\n'
            'db_name = "logging_test"\n'
        )
        if level is not None:
            text += f'log_level = "{level}"\n'
        self.config_path.write_text(text)

    async def run_cli(self, *args):
        """Run through argparse rather than replacing its result."""
        argv = ["cyhy-cvesync", "--config-file", str(self.config_path), *args]
        with patch.object(sys, "argv", argv):
            await main_async()

    async def test_cli_uses_configured_level(self):
        """An omitted CLI flag must leave the configured DEBUG level effective."""
        self.write_config("debug")
        await self.run_cli()
        self.assertEqual(self.logging.call_args, call("debug"))
        self.database.assert_awaited_once_with(
            "mongodb://localhost:27017", "logging_test"
        )
        self.process.assert_awaited_once()
        self.shutdown.assert_called_once()

    async def test_cli_explicit_long_option_overrides_config(self):
        """The long CLI option takes priority over the configuration."""
        self.write_config("debug")
        await self.run_cli("--log-level", "warning")
        self.logging.assert_called_once_with("warning")

    async def test_cli_explicit_short_option_overrides_config(self):
        """An explicit INFO level remains an override rather than a default."""
        self.write_config("debug")
        await self.run_cli("-l", "info")
        self.logging.assert_called_once_with("info")

    async def test_cli_defaults_to_info(self):
        """The CLI retains INFO when neither source specifies a level."""
        self.write_config()
        await self.run_cli()
        self.logging.assert_called_once_with("info")

    async def test_library_uses_configured_level(self):
        """Library callers without an override also honor the configuration."""
        self.write_config("debug")
        await do_cve_sync(str(self.config_path))
        self.assertEqual(self.logging.call_args, call("debug"))

    async def test_library_explicit_level_overrides_config(self):
        """Library callers retain their explicit logging override."""
        self.write_config("debug")
        await do_cve_sync(str(self.config_path), "error")
        self.logging.assert_called_once_with("error")

    async def test_library_defaults_to_info(self):
        """The no-override library entrypoint uses the documented INFO fallback."""
        self.write_config()
        await do_cve_sync(str(self.config_path))
        self.logging.assert_called_once_with("info")

    async def test_invalid_cli_level_stops_before_sync(self):
        """Argparse rejects unsupported CLI levels before loading or syncing."""
        self.write_config("debug")
        with self.assertRaises(SystemExit) as error:
            await self.run_cli("--log-level", "verbose")
        self.assertEqual(error.exception.code, 2)
        self.database.assert_not_awaited()
        self.process.assert_not_awaited()

    async def test_invalid_configured_level_stops_before_sync(self):
        """A configured level rejected by logging must not start synchronization."""
        self.write_config("verbose")

        def validate_level(level):
            if level == "verbose":
                raise ValueError("Unknown level: 'VERBOSE'")

        self.logging.side_effect = validate_level
        with self.assertRaises(ValueError):
            await self.run_cli()
        self.database.assert_not_awaited()
        self.process.assert_not_awaited()

    async def test_explicit_level_bypasses_unused_invalid_config_level(self):
        """A valid override keeps an unused configured level from being applied."""
        self.write_config("verbose")
        await self.run_cli("-l", "warning")
        self.logging.assert_called_once_with("warning")

    async def test_missing_config_stops_before_sync(self):
        """Configuration errors continue to exit before touching the database."""
        # Discovery falls back to user/system configuration even when the
        # explicit file is missing. Isolate that external filesystem boundary.
        with (
            patch(
                f"{get_config.__module__}.find_config_file",
                side_effect=FileNotFoundError,
            ),
            self.assertRaises(SystemExit) as error,
        ):
            await self.run_cli()
        self.assertEqual(error.exception.code, 1)
        self.database.assert_not_awaited()
        self.process.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
