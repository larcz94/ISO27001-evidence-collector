"""Collector registry. Add new sources (m365, gitlab, linux, ...) here."""

from __future__ import annotations

from .base import BaseCollector


def get_collector(source: str, **kwargs) -> BaseCollector:
    if source == "aws":
        from .aws import AWSCollector
        return AWSCollector(**kwargs)
    if source == "lightsail":
        from .lightsail import LightsailCollector
        return LightsailCollector(**kwargs)
    raise ValueError(f"Unknown source '{source}'. Available: {', '.join(AVAILABLE)}")


AVAILABLE = ["aws", "lightsail"]
