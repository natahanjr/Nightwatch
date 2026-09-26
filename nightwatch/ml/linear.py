"""Linear classifiers: L2-regularised logistic regression and a linear SVM.

Both are trained with stochastic gradient descent over a fixed shuffled order,
so a given seed always produces the same model - which is what lets the tests
assert exact metric values.

:class:`LogisticRegression` optimises the binary cross-entropy the paper
writes as ``P(y=1|x) = sigma(w^T x + b)`` and supports class weighting, which
matters here because benign traffic outnumbers malicious traffic by orders of
magnitude in every real capture; without ``class_weight='balanced'`` the
prior term simply wins.

:class:`LinearSVC` optimises the squared hinge loss and has no probability
output, so it exposes ``predict`` via its decision boundary. It is included
because it is the paper's second baseline and because a hinge-trained linear
model is a useful contrast to the probabilistic one: same features, different
loss, genuinely different failure modes.
"""

import math

from .base import Model, register
from .linalg import (dot, log_loss, sigmoid, squared_hinge, zeros)
from .rng import RNG, shuffle


@register
class LogisticRegression(Model):
    """Binary logistic regression trained with SGD.

    :param learning_rate: base step size for SGD.
    :param epochs: full passes over the data.
    :param l2: L2 penalty on the weights (not the intercept).
    :param class_weight: ``None``, ``"balanced"``, or a ``{0: w, 1: w}`` dict.
    :param momentum: heavy-ball momentum in [0, 1).
    :param seed: seeds the shuffling, so runs are reproducible.
    """

    name = "logistic"
    probabilistic = True

    def __init__(self, learning_rate=0.1, epochs=200, l2=1e-3,
                 class_weight=None, momentum=0.9, seed=42,
                 feature_names=None, **kwargs):
        super().__init__(feature_names=feature_names,
                         params={"learning_rate": learning_rate,
                                 "epochs": epochs, "l2": l2,
                                 "class_weight": class_weight,
                                 "momentum": momentum, "seed": seed})
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.l2 = l2
        self.class_weight = class_weight
        self.momentum = momentum
        self.seed = seed
        self.weights = None
        self.bias = 0.0
        self.history_ = []

    # -- training -----------------------------------------------------------

    def fit(self, X, y):
        scaled, labels = self._prepare_fit(X, y)
        width = self.n_features
        weights = zeros(width)
        bias = 0.0
        velocity = zeros(width)
        bias_velocity = 0.0
        weights_ = self._sample_weights(labels)

        rng = RNG(self.seed)
        order = list(range(len(scaled)))
        for epoch in range(self.epochs):
            shuffle(order, rng)
            rate = self.learning_rate / (1.0 + 0.01 * epoch)
            for i in order:
                row, target = scaled[i], labels[i]
                p = sigmoid(dot(weights, row) + bias)
                error = (p - target) * weights_[i]
                grad = [error * value for value in row]
                for j in range(width):
                    grad[j] += self.l2 * weights[j]
                velocity = [self.momentum * v + rate * g
                            for v, g in zip(velocity, grad)]
                weights = [w - v for w, v in zip(weights, velocity)]
                bias_velocity = self.momentum * bias_velocity + rate * error
                bias -= bias_velocity
            self.history_.append(log_loss(
                labels, [sigmoid(dot(weights, r) + bias) for r in scaled]))
        self.weights = weights
        self.bias = bias
        self.fitted = True
        return self

    def _sample_weights(self, labels):
        """Per-sample loss weights for class balancing."""
        if not self.class_weight:
            return [1.0] * len(labels)
        positives = sum(1 for v in labels if v == 1)
        negatives = len(labels) - positives
        if self.class_weight == "balanced":
            weight_pos = len(labels) / (2.0 * positives) if positives else 1.0
            weight_neg = len(labels) / (2.0 * negatives) if negatives else 1.0
            return [weight_pos if v == 1 else weight_neg for v in labels]
        return [float(self.class_weight.get(v, 1.0)) for v in labels]

    # -- prediction ---------------------------------------------------------

    def decision_function(self, X):
        self._require_fitted()
        return [dot(self.weights, row) + self.bias
                for row in self._apply_scaler(X)]

    def coefficients(self):
        """``(weights, intercept)`` for the explainability layer."""
        self._require_fitted()
        return list(self.weights), self.bias

    def load_state(self, payload):
        self.weights = payload.get("weights")
        self.bias = payload.get("bias", 0.0)
        self.history_ = payload.get("history", [])
        return self

    def to_dict(self):
        payload = super().to_dict()
        payload.update({"weights": self.weights, "bias": self.bias,
                        "history": self.history_})
        return payload

    def _require_fitted(self):
        if not self.fitted or self.weights is None:
            raise RuntimeError(f"{self.name} has not been fitted yet")


@register
class LinearSVC(Model):
    """Linear support vector classifier trained with squared-hinge SGD.

    Exposes a decision function but no probability: the margin is a distance
    from a hyperplane, not a likelihood.
    """

    name = "linear-svm"
    probabilistic = False

    def __init__(self, learning_rate=0.01, epochs=200, l2=1e-4, seed=42,
                 feature_names=None, **kwargs):
        super().__init__(feature_names=feature_names,
                         params={"learning_rate": learning_rate,
                                 "epochs": epochs, "l2": l2, "seed": seed})
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.l2 = l2
        self.seed = seed
        self.weights = None
        self.bias = 0.0
        self.losses_ = []

    def fit(self, X, y):
        scaled, labels = self._prepare_fit(X, y)
        signs = [1.0 if v == 1 else -1.0 for v in labels]
        width = self.n_features
        weights = zeros(width)
        bias = 0.0
        rng = RNG(self.seed)
        order = list(range(len(scaled)))
        for epoch in range(self.epochs):
            shuffle(order, rng)
            rate = self.learning_rate / (1.0 + 0.001 * epoch)
            for i in order:
                row, sign = scaled[i], signs[i]
                margin = sign * (dot(weights, row) + bias)
                if margin < 1.0:
                    # d/dw of (1 - y f)^2 is -2 y (1 - y f) x
                    scale_factor = -2.0 * sign * (1.0 - margin)
                    for j in range(width):
                        weights[j] -= rate * (scale_factor * row[j]
                                              + self.l2 * weights[j])
                    bias -= rate * scale_factor
            self.losses_.append(math.fsum(
                squared_hinge(sign * (dot(weights, r) + bias), 1.0)
                for r, sign in zip(scaled, signs)) / len(scaled))
        self.weights = weights
        self.bias = bias
        self.fitted = True
        return self

    def decision_function(self, X):
        if not self.fitted or self.weights is None:
            raise RuntimeError(f"{self.name} has not been fitted yet")
        return [dot(self.weights, row) + self.bias
                for row in self._apply_scaler(X)]

    def coefficients(self):
        if not self.fitted or self.weights is None:
            raise RuntimeError(f"{self.name} has not been fitted yet")
        return list(self.weights), self.bias

    def predict_proba(self, X):
        """Rank-normalised margin mapped to [0, 1].

        Not a calibrated probability; the monotonic squash exists only so the
        model can be scored by the same ROC code as the others. It is
        deliberately monotone, so AUC and ranking metrics stay meaningful.
        """
        scores = self.decision_function(X)
        if not scores:
            return []
        low, high = min(scores), max(scores)
        span = high - low
        if span <= 0:
            return [[0.5, 0.5] for _ in scores]
        return [[1.0 - t, t]
                for t in ((s - low) / span for s in scores)]

    def load_state(self, payload):
        self.weights = payload.get("weights")
        self.bias = payload.get("bias", 0.0)
        self.losses_ = payload.get("losses", [])
        return self

    def to_dict(self):
        payload = super().to_dict()
        payload.update({"weights": self.weights, "bias": self.bias,
                        "losses": self.losses_})
        return payload


__all__ = ["LogisticRegression", "LinearSVC"]
