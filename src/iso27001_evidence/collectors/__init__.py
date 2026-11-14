"""Collector registry. Add new sources (m365, gitlab, linux, ...) here."""

from __future__ import annotations

from .base import BaseCollector


def collector_class(source: str) -> type[BaseCollector]:
    if source == "aws":
        from .aws import AWSCollector
        return AWSCollector
    if source == "lightsail":
        from .lightsail import LightsailCollector
        return LightsailCollector
    raise ValueError(f"Unknown source '{source}'. Available: {', '.join(AVAILABLE)}")


def get_collector(source: str, **kwargs) -> BaseCollector:
    return collector_class(source)(**kwargs)


AVAILABLE = ["aws", "lightsail"]
