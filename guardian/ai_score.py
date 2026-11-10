"""The "AI" part: a tiny machine-learning model that scores how risky a file is.

WHAT it is: logistic regression, the simplest real ML classifier. It gives each
heuristic feature a weight, adds them up, and squashes the total into a
probability between 0 and 1.

    probability = 1 / (1 + e^-(bias + w1*x1 + w2*x2 + ...))

WHY this and not a giant neural network: you can read it, debug it, train it
in pure Python with no libraries, and explain every verdict ("it was flagged
because of features A and B"). Explainability matters in security. Real
products add much bigger models later, but they all follow the same loop:
extract features -> score -> compare to a threshold -> learn from mistakes.

HOW it "updates itself": train() re-fits the weights from labelled examples
(clean / malicious). Feed it new labelled samples and the weights move.
"""

import json
import math
from typing import Iterable

from . import config
from .heuristics import FEATURES

# Starting weights, set by hand from security knowledge so the app is useful
# on day one, before you have any training data of your own.
DEFAULT_MODEL = {
    "bias": -3.0,
    "weights": {
        "double_ext": 3.5,
        "rtlo": 4.0,
        "disguised_exec": 3.5,
        "is_exec": 0.8,
        "high_entropy_exec": 2.0,
        "script_hits": 1.8,
        "macro_doc": 2.0,
        "exec_in_temp": 1.0,
        "hidden_exec": 1.0,
        # v0.2 features. One severity-2 rule hit (value 2.0) -> 73% "suspicious";
        # one severity-3 hit (3.0) -> 95% "malicious"; severity-1 stays clean.
        "rule_hits": 2.0,
        "encrypted_archive": 1.5,
        "archive_bomb": 2.0,
    },
}


def _sigmoid(z: float) -> float:
    # Clamp so math.exp never overflows on extreme values.
    z = max(-30.0, min(30.0, z))
    return 1.0 / (1.0 + math.exp(-z))


class Model:
    def __init__(self, bias: float, weights: dict[str, float]) -> None:
        self.bias = bias
        # A model file saved by an older version lacks the newer features. Fall
        # back to the shipped default weight (not 0) so upgrades keep new detections.
        defaults = DEFAULT_MODEL["weights"]
        self.weights = {k: weights.get(k, defaults.get(k, 0.0)) for k in FEATURES}

    @classmethod
    def load(cls) -> "Model":
        path = config.model_path()
        if path.exists():
            try:
                d = json.loads(path.read_text())
                return cls(d["bias"], d["weights"])
            except (KeyError, json.JSONDecodeError, OSError):
                pass
        return cls(DEFAULT_MODEL["bias"], DEFAULT_MODEL["weights"])

    def save(self) -> None:
        config.model_path().write_text(
            json.dumps({"bias": self.bias, "weights": self.weights}, indent=2)
        )

    def predict(self, features: dict) -> float:
        z = self.bias + sum(self.weights[k] * features.get(k, 0.0) for k in FEATURES)
        return _sigmoid(z)

    def top_factors(self, features: dict, n: int = 3) -> list[tuple[str, float]]:
        """Which features pushed the score up the most (for explanations)."""
        contrib = [(k, self.weights[k] * features.get(k, 0.0)) for k in FEATURES]
        return sorted([c for c in contrib if c[1] > 0], key=lambda c: -c[1])[:n]

    def train(self, samples: Iterable[tuple[dict, int]], epochs: int = 200,
              lr: float = 0.1) -> None:
        """Gradient descent: nudge weights to reduce mistakes.

        For each labelled example (features, label 1=bad / 0=clean):
            error = label - predicted_probability
            weight += learning_rate * error * feature_value
        Repeat many times. This is the core of how most ML models learn.
        """
        data = list(samples)
        if not data:
            return
        for _ in range(epochs):
            for feats, label in data:
                err = label - self.predict(feats)
                self.bias += lr * err
                for k in FEATURES:
                    self.weights[k] += lr * err * feats.get(k, 0.0)
