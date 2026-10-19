"""ControlLoop Community CLI."""

from importlib.metadata import PackageNotFoundError, version


def _distribution_version() -> str:
    """Return the installed version or a safe source-tree fallback."""
    try:
        return version("controlloop")
    except PackageNotFoundError:
        return "0.0.0+uninstalled"


__version__ = _distribution_version()

__all__ = ["__version__"]
