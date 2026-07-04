"""Utility functions and logging setup for AccessProbe."""

import logging
from rich.logging import RichHandler


def get_logger(name: str = "accessprobe") -> logging.Logger:
    """Get a configured logger with rich output."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = RichHandler(rich_tracebacks=True, show_time=True)
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger


def setup_logging(level: int = logging.INFO) -> None:
    """Setup global logging configuration."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True)]
    )
