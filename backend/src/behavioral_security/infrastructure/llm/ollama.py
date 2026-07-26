"""Bounded Ollama client that selects only supplied evidence identifiers."""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.request import Request, urlopen

from behavioral_security.core.enums import AnalystQuestion


@dataclass(frozen=True, slots=True)
class OllamaEvidenceSelector:
    """Use Ollama to select relevant grounded facts without authoring facts."""

    base_url: str
    model: str
    timeout_seconds: float

    def select(
        self,
        question: AnalystQuestion,
        facts: Mapping[str, str],
        recommendations: Mapping[str, str],
    ) -> tuple[Sequence[str], Sequence[str]]:
        """Return exact supplied identifiers selected by the local model."""

        prompt = (
            "You are a SOC investigation evidence selector. Select only identifiers from "
            "the supplied facts and recommendations that directly answer the analyst "
            "question. Never create prose, facts, identifiers, users, IPs, locations, "
            "devices, resources, or attack evidence. Return JSON only with this schema: "
            '{"fact_ids":["existing_id"],"recommendation_ids":["existing_id"]}. '
            f"Question: {question.value}\n"
            f"Facts: {json.dumps(dict(facts), sort_keys=True)}\n"
            f"Recommendations: {json.dumps(dict(recommendations), sort_keys=True)}"
        )
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0, "seed": 1729},
            }
        ).encode("utf-8")
        request = Request(
            f"{self.base_url.rstrip('/')}/api/generate",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            envelope = json.loads(response.read().decode("utf-8"))
        selection = json.loads(str(envelope["response"]))
        fact_ids = selection.get("fact_ids", [])
        recommendation_ids = selection.get("recommendation_ids", [])
        if not isinstance(fact_ids, list) or not isinstance(recommendation_ids, list):
            raise ValueError("Ollama returned an invalid evidence selection")
        return tuple(map(str, fact_ids)), tuple(map(str, recommendation_ids))
