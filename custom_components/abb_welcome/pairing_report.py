"""Copyable, redacted debug report for the pairing config flow."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from .redaction import redact_log_value

_INTEGRATION_VERSION = json.loads(
    (Path(__file__).parent / "manifest.json").read_text(encoding="utf-8")
)["version"]

# The report is rendered inside a config-flow dialog, so keep the start of
# the pairing (where most failures happen) and the most recent activity.
HEAD_LINES = 150
TAIL_LINES = 60
MAX_LINE_CHARS = 600


class PairingReport(logging.Handler):
    """Collect DEBUG records from the pairing loggers while work runs.

    Records reach this handler after the loggers' redaction filter, and the
    message is redacted once more before it is kept. Only the message is
    redacted because the redaction treats ``HH:MM:SS`` like an IPv6 address.
    """

    def __init__(self, loggers: tuple[logging.Logger, ...], header: str) -> None:
        super().__init__(logging.DEBUG)
        self._loggers = loggers
        self._header = f"ABB Welcome {_INTEGRATION_VERSION}, {header}"
        self._lines: list[str] = []

    @contextmanager
    def capture(self) -> Iterator[None]:
        """Temporarily attach to the loggers and enable their DEBUG output."""
        previous_levels = [(logger, logger.level) for logger in self._loggers]
        for logger in self._loggers:
            logger.addHandler(self)
            if not logger.isEnabledFor(logging.DEBUG):
                logger.setLevel(logging.DEBUG)
        try:
            yield
        finally:
            for logger, level in previous_levels:
                logger.removeHandler(self)
                logger.setLevel(level)

    def emit(self, record: logging.LogRecord) -> None:
        text = record.getMessage()
        if record.exc_info:
            text = f"{text}\n{logging.Formatter().formatException(record.exc_info)}"
        created = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"{created}.{int(record.msecs):03d} {record.levelname} {record.name}: "
        for index, line in enumerate(str(redact_log_value(text)).splitlines()):
            self._lines.append(
                ((prefix if index == 0 else "    ") + line)[:MAX_LINE_CHARS]
            )

    def render(self) -> str:
        """Return a Markdown code block for a flow description, or ``""``."""
        if not self._lines:
            return ""
        lines = self._lines
        if len(lines) > HEAD_LINES + TAIL_LINES:
            omitted = len(lines) - HEAD_LINES - TAIL_LINES
            lines = [
                *lines[:HEAD_LINES],
                f"... {omitted} lines omitted ...",
                *lines[-TAIL_LINES:],
            ]
        body = "\n".join([self._header, *lines]).replace("```", "'''")
        return (
            "\n\n**Debug report** (copy everything in the box when reporting "
            f"an issue; secrets are redacted):\n\n```text\n{body}\n```"
        )
