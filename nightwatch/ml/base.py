"""Shared model interface: scaling, prediction, and JSON persistence.

Every estimator in :mod:`nightwatch.ml` follows the same contract, so they are
interchangeable in :func:`~nightwatch.ml.evaluate.evaluate` and in the
``nightwatch ml`` CLI:

* ``fit(X, y)`` trains and returns ``self``
* ``decision_function(X)`` returns a real-valued score, high meaning malicious
* ``predict_proba(X)`` returns ``[P(benign), P(malicious)]``
* ``predict(X)`` returns 0/1 labels
* ``to_dict()`` / ``from_dict()`` round-trip through JSON

A model records the feature names it was trained on and refuses to score a
matrix whose width differs, so a stale model fails loudly instead of silently
computing on the wrong columns.
"""

import json
import os
import tempfile

from .features import FEATURES
from .linalg import StandardScaler, sigmoid

# Below this many rows a fitted model is treated as unreliable, not as a
# license to return arbitrary numbers.
_MIN_TRAIN_ROWS = 2


class Model:
    """Base class providing scaling, prediction plumbing and serialisation."""

    name = "model"
    #: True when the estimator consumes standardised input.
    needs_scaling = True
    #: True when the estimator can produce a calibrated probability.
    probabilistic = True

    def __init__(self, feature_names=None, scaler=None, fitted=False,
                 params=None):
        self.feature_names = list(feature_names or FEATURES)
        self.scaler = scaler
        self.fitted = fitted
        self.params = dict(params or {})

    # -- feature plumbing ---------------------------------------------------

    @property
    def n_features(self):
        return len(self.feature_names)

    def _check_width(self, X):
        for row in X:
            if len(row) != self.n_features:
                raise ValueError(
                    f"{self.name} was trained on {self.n_features} features "
                    f"but got a row of {len(row)}; the feature set changed "
                    f"since training (expected: {', '.join(self.feature_names)})"
                )

    def _fit_scaler(self, X):
        if self.needs_scaling:
            self.scaler = StandardScaler().fit(X)
            return self.scaler.transform(X)
        return [list(row) for row in X]

    def _apply_scaler(self, X):
        self._check_width(X)
        if self.scaler is not None:
            return self.scaler.transform(X)
        return [list(row) for row in X]

    def _prepare_fit(self, X, y):
        X = [list(row) for row in X]
        if len(X) < _MIN_TRAIN_ROWS:
            raise ValueError(f"need at least {_MIN_TRAIN_ROWS} training rows, "
                             f"got {len(X)}")
        if len(X) != len(y):
            raise ValueError(f"X has {len(X)} rows but y has {len(y)}")
        self._check_width(X)
        return self._fit_scaler(X), list(y)

    # -- prediction ---------------------------------------------------------

    def decision_function(self, X):
        """Signed score; positive means malicious. Must be overridden."""
        raise NotImplementedError

    def predict_proba(self, X):
        """Two-column probability matrix, ``[benign, malicious]``."""
        scores = self.decision_function(X)
        return [[1.0 - p, p] for p in (sigmoid(s) for s in scores)]

    def predict(self, X, threshold=0.5):
        """Hard labels. Uses ``predict_proba`` when available, else the score."""
        if self.probabilistic:
            return [1 if row[1] >= threshold else 0 for row in
                    self.predict_proba(X)]
        return [1 if score >= 0.0 else 0 for score in
                self.decision_function(X)]

    def score(self, X, y):
        """Mean accuracy against ``y``."""
        predicted = self.predict(X)
        if not y:
            return 0.0
        hits = sum(1 for p, t in zip(predicted, y) if p == t)
        return hits / len(y)

    def positive_rate(self, X):
        """Fraction of rows predicted malicious."""
        rows = list(X)
        return self.score(rows, [1] * len(rows)) if rows else 0.0

    # -- serialisation ------------------------------------------------------

    def to_dict(self):
        return {
            "class": type(self).__name__,
            "name": self.name,
            "feature_names": self.feature_names,
            "fitted": self.fitted,
            "params": self.params,
            "scaler": (None if self.scaler is None else
                       {"mu": self.scaler.mu_, "sigma": self.scaler.sigma_}),
        }

    @classmethod
    def from_dict(cls, payload):
        """Rebuild a model from :meth:`to_dict` output.

        The constructor is re-run with the recorded parameters so every
        instance attribute is restored, not just the learned weights. Unknown
        parameter names are dropped rather than raising, so a payload written
        by an older version still loads.
        """
        import inspect
        accepted = set(inspect.signature(cls.__init__).parameters) - {"self"}
        params = {k: v for k, v in (payload.get("params") or {}).items()
                  if k in accepted}
        model = cls(feature_names=payload.get("feature_names"), **params)
        model.fitted = payload.get("fitted", False)
        scaler = payload.get("scaler")
        if scaler:
            model.scaler = StandardScaler()
            model.scaler.mu_ = scaler["mu"]
            model.scaler.sigma_ = scaler["sigma"]
        model.load_state(payload)
        return model

    def load_state(self, payload):
        """Restore subclass-specific weights. Must be overridden."""
        return self

    def save(self, path):
        """Write the model to ``path`` as JSON, atomically."""
        directory = os.path.dirname(os.path.abspath(path)) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)
        os.replace(tmp, path)
        return path

    @classmethod
    def load(cls, path):
        """Read a model back from ``path``."""
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        target = REGISTRY.get(payload.get("class"), cls)
        return target.from_dict(payload)

    def describe(self):
        return {"model": self.name, "features": self.n_features,
                "fitted": self.fitted, "params": self.params}

    def __repr__(self):
        state = "fitted" if self.fitted else "unfitted"
        return f"<{type(self).__name__} {state} d={self.n_features}>"


REGISTRY = {}


def register(cls):
    """Class decorator registering a model type for :meth:`Model.load`."""
    REGISTRY[cls.__name__] = cls
    return cls


def load_model(path):
    """Load any saved model, dispatching on its recorded class name."""
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    target = REGISTRY.get(payload.get("class"))
    if target is None:
        raise ValueError(f"unknown model type "
                         f"{payload.get('class')!r}; known types: "
                         f"{', '.join(sorted(REGISTRY))}")
    return target.from_dict(payload)
