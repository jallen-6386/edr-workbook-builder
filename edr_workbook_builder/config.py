"""
INI-style configuration file support for EDR Workbook Builder.

Config is loaded from up to three sources in priority order (later wins):
  1. Global:   ~/.config/edr-workbook-builder/config.ini
  2. Local:    .edr-workbook-builder.ini  (current working directory)
  3. Explicit: path passed via --config FILE

Call load_config() to get a ConfigParser, apply_config_defaults(args, cfg) to
fill unset argparse flags from the config, and save_config(args) to write the
current settings to the local config file.
"""

import configparser
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CONFIG_GLOBAL_PATH = Path.home() / ".config" / "edr-workbook-builder" / "config.ini"
CONFIG_LOCAL_NAME = ".edr-workbook-builder.ini"

_SECTION = "defaults"

_DEFAULTS: dict[str, dict[str, str]] = {
    _SECTION: {
        "summary":           "false",
        "timeline":          "false",
        "highlight":         "false",
        "escape_formulas":   "false",
        "recursive":         "false",
        "add_source_column": "false",
        "attck":             "false",
        "process_tree":      "false",
    },
    "analyst": {
        "name": "",
    },
}

# Boolean flags that can be set via config.
BOOL_FLAGS: frozenset[str] = frozenset(_DEFAULTS[_SECTION])


def load_config(extra_path: Optional[Path] = None) -> configparser.ConfigParser:
    """Load config from global → local → extra_path (later files override earlier)."""
    cfg = configparser.ConfigParser()
    cfg.read_dict(_DEFAULTS)

    paths: list[Path] = [CONFIG_GLOBAL_PATH, Path(CONFIG_LOCAL_NAME)]
    if extra_path:
        paths.append(extra_path)

    for p in paths:
        if p.exists():
            cfg.read(p)
            logger.debug("Loaded config: %s", p)

    return cfg


def apply_config_defaults(args, cfg: configparser.ConfigParser) -> None:
    """
    Fill argparse Namespace fields that are still None from config values.

    Only boolean flags not explicitly passed by the user (value is None when
    using BooleanOptionalAction without a default) are updated.  Any flag that
    remains None after config lookup is set to False.
    """
    for flag in BOOL_FLAGS:
        if getattr(args, flag, None) is None:
            try:
                setattr(args, flag, cfg.getboolean(_SECTION, flag))
            except (configparser.NoOptionError, ValueError):
                setattr(args, flag, False)

    # Resolve any remaining None → False (flags absent from config entirely).
    for flag in BOOL_FLAGS:
        if getattr(args, flag, None) is None:
            setattr(args, flag, False)


def save_config(args, path: Optional[Path] = None) -> Path:
    """
    Write current boolean flag values to a config file.

    Defaults to the local config (.edr-workbook-builder.ini in cwd).
    Merges with any existing file so non-flag sections are preserved.
    Returns the path that was written.
    """
    target = path or Path(CONFIG_LOCAL_NAME)

    cfg = configparser.ConfigParser()
    cfg.read_dict(_DEFAULTS)
    if target.exists():
        cfg.read(target)

    if not cfg.has_section(_SECTION):
        cfg.add_section(_SECTION)

    for flag in BOOL_FLAGS:
        val = getattr(args, flag, False)
        cfg.set(_SECTION, flag, "true" if val else "false")

    with open(target, "w") as fh:
        cfg.write(fh)

    logger.info("Config saved: %s", target)
    return target
