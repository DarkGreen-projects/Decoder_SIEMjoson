from __future__ import annotations

from abc import ABC, abstractmethod

from decoder_siem.models import Artifact, EnrichmentResult


class Enricher(ABC):
    name: str

    @abstractmethod
    def supports(self, artifact: Artifact) -> bool:
        ...

    @abstractmethod
    def enrich(self, artifact: Artifact) -> EnrichmentResult:
        ...
