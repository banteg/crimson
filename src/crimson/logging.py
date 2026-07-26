from __future__ import annotations

import datetime as dt
import logging
import os
import sys
from pathlib import Path

import structlog

_LEVELS: dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


def resolve_log_level(value: str | int) -> int:
    if isinstance(value, int):
        return int(value)
    level_name = str(value).strip().lower()
    resolved = _LEVELS.get(level_name)
    if resolved is None:
        supported = ", ".join(sorted(_LEVELS))
        raise ValueError(f"unsupported log level {value!r}; expected one of: {supported}")
    return int(resolved)


def default_component_log_path(*, base_dir: Path, component: str) -> Path:
    component_name = str(component).strip().lower() or "app"
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    return base_dir / "logs" / component_name / f"{component_name}-pid{os.getpid()}-{timestamp}.log"


def _configure_structlog(*, level: int) -> list[structlog.typing.Processor]:
    processors: list[structlog.typing.Processor] = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            *processors,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(int(level)),
        cache_logger_on_first_use=True,
    )
    return processors


def ensure_structlog_stdlib_defaults() -> None:
    config = structlog.get_config()
    logger_factory = config.get("logger_factory")
    if isinstance(logger_factory, structlog.stdlib.LoggerFactory):
        return
    _configure_structlog(level=logging.INFO)


def configure_component_logging(
    *,
    logger_name: str,
    component: str,
    log_file: Path,
    level: str | int = "info",
) -> Path:
    level_no = resolve_log_level(level)
    processors = _configure_structlog(level=int(level_no))

    resolved_log_file = Path(log_file).expanduser()
    resolved_log_file.parent.mkdir(parents=True, exist_ok=True)

    console_formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=list(processors),
        processor=structlog.dev.ConsoleRenderer(colors=bool(sys.stdout.isatty())),
    )
    file_formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=list(processors),
        processor=structlog.processors.JSONRenderer(sort_keys=True),
    )

    logger = logging.getLogger(str(logger_name))
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(int(level_no))

    stream_handler = logging.StreamHandler(stream=sys.stdout)
    stream_handler.setLevel(int(level_no))
    stream_handler.setFormatter(console_formatter)

    file_handler = logging.FileHandler(resolved_log_file, mode="a", encoding="utf-8")
    file_handler.setLevel(int(level_no))
    file_handler.setFormatter(file_formatter)

    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)

    structlog.stdlib.get_logger(str(logger_name)).info(
        "logging_configured",
        component=str(component),
        logger_name=str(logger_name),
        log_file=str(resolved_log_file),
        level=logging.getLevelName(level_no).lower(),
    )
    return resolved_log_file


__all__ = [
    "configure_component_logging",
    "default_component_log_path",
    "ensure_structlog_stdlib_defaults",
    "resolve_log_level",
]
