"""Vector and loss math in pure Python.

Everything the models need that would normally come from NumPy: dot products,
elementwise passes, stable logistic and softmax, and the two normalisers.

The important design choice is :class:`StandardScaler`. Tree ensembles want raw
features (a split threshold is a raw threshold), while gradient-based models
need zero-centred, unit-scale inputs or SGD will diverge on features measured
in different units. :class:`MinMaxScaler` is kept because it is the
normalisation the underlying paper specifies, so the same results can be
reproduced with that formula when comparing against the published numbers.
"""

import math


# -- vector primitives -----------------------------------------------------


def zeros(n):
    return [0.0] * n


def dot(a, b):
    """Dot product, tolerant of length mismatch between the two vectors."""
    return math.fsum(x * y for x, y in zip(a, b))


def add(a, b):
    return [x + y for x, y in zip(a, b)]


def sub(a, b):
    return [x - y for x, y in zip(a, b)]


def scale(a, factor):
    return [x * factor for x in a]


def mean(values):
    values = list(values)
    return math.fsum(values) / len(values) if values else 0.0


def variance(values, mu=None):
    values = list(values)
    if len(values) < 2:
        return 0.0
    mu = mean(values) if mu is None else mu
    return math.fsum((x - mu) ** 2 for x in values) / len(values)


def stdev(values, mu=None):
    return math.sqrt(variance(values, mu))


def clip(value, low, high):
    return low if value < low else high if value > high else value


def sigmoid(z):
    """Logistic function, overflow-safe for large |z|."""
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    exp_z = math.exp(z)
    return exp_z / (1.0 + exp_z)


def logit(p, eps=1e-12):
    """Inverse of :func:`sigmoid`, clamped away from 0 and 1."""
    p = clip(p, eps, 1.0 - eps)
    return math.log(p / (1.0 - p))


def softmax(scores):
    """Numerically stable softmax over a list of scores."""
    if not scores:
        return []
    top = max(scores)
    exps = [math.exp(s - top) for s in scores]
    total = math.fsum(exps)
    return [e / total for e in exps]


def entropy(text):
    """Shannon entropy of a string, in bits per character.

    Used as a URL feature: random-looking hostnames carry far more entropy per
    character than dictionary words, so this separates an algorithmically
    generated domain from ``login.paypal.com``.
    """
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -math.fsum((c / total) * math.log2(c / total)
                      for c in counts.values())


def log1p_scaled(value, cap=1e9):
    """log1p of a non-negative count, saturating so one huge flow cannot
    dominate a standardisation pass."""
    return math.log1p(min(abs(float(value)), cap))


# -- normalisation ---------------------------------------------------------


class MinMaxScaler:
    """Min-max normalisation to [0, 1] (equation 2 of the source paper).

    ``fit`` records the per-feature extremes; ``transform`` rescales. A
    constant feature maps to 0 rather than dividing by zero.
    """

    def __init__(self):
        self.min_ = None
        self.max_ = None

    def fit(self, X):
        if not X:
            raise ValueError("cannot fit a scaler on an empty matrix")
        width = len(X[0])
        self.min_ = [min(row[i] for row in X) for i in range(width)]
        self.max_ = [max(row[i] for row in X) for i in range(width)]
        return self

    def transform(self, X):
        if self.min_ is None:
            raise RuntimeError("MinMaxScaler must be fitted before transform")
        out = []
        for row in X:
            scaled = []
            for value, low, high in zip(row, self.min_, self.max_):
                span = high - low
                scaled.append(0.0 if span <= 0 else (value - low) / span)
            out.append(scaled)
        return out

    def fit_transform(self, X):
        return self.fit(X).transform(X)


class StandardScaler:
    """Zero mean, unit variance, for gradient-based models."""

    def __init__(self, epsilon=1e-9):
        self.mu_ = None
        self.sigma_ = None
        self.epsilon = epsilon

    def fit(self, X):
        if not X:
            raise ValueError("cannot fit a scaler on an empty matrix")
        width = len(X[0])
        self.mu_ = [mean([row[i] for row in X]) for i in range(width)]
        self.sigma_ = [max(stdev([row[i] for row in X], self.mu_[i]),
                           self.epsilon) for i in range(width)]
        return self

    def transform(self, X):
        if self.mu_ is None:
            raise RuntimeError("StandardScaler must be fitted before transform")
        return [[(value - mu) / sigma
                 for value, mu, sigma in zip(row, self.mu_, self.sigma_)]
                for row in X]

    def fit_transform(self, X):
        return self.fit(X).transform(X)


# -- losses ----------------------------------------------------------------


def log_loss(y_true, probabilities, eps=1e-15):
    """Mean binary cross-entropy, the loss logistic regression minimises."""
    if not y_true:
        return 0.0
    total = 0.0
    for target, p in zip(y_true, probabilities):
        p = clip(p, eps, 1.0 - eps)
        total += -(target * math.log(p) + (1 - target) * math.log(1.0 - p))
    return total / len(y_true)


def squared_hinge(margin, label):
    """Squared hinge loss for ``label`` in {-1, +1}."""
    return max(0.0, 1.0 - label * margin) ** 2


def mean_squared_error(a, b):
    pairs = list(zip(a, b))
    if not pairs:
        return 0.0
    return math.fsum((x - y) ** 2 for x, y in pairs) / len(pairs)
