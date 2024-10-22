"""The cyhy_nvdsync library."""

# We disable the following Flake8 checks:
# - "Module level import not at top of file (E402)" here because the constants
#   need to be defined early to prevent a circular import issue.
# - "Module imported but unused (F401)" here because although this import is not
#   directly used, it populates the value package_name.__version__, which is
#   used to get version information about this Python package.

DEFAULT_NVD_URL_PATTERN = (
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
)

from ._version import __version__  # noqa: F401, E402
from .main import do_nvd_sync  # noqa: E402

__all__ = [DEFAULT_NVD_URL_PATTERN, "do_nvd_sync"]
