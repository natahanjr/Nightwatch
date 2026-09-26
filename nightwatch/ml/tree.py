"""Tree ensembles: CART decision tree, Random Forest, Gradient Boosting.

These are the paper's headline models, implemented from scratch because
Nightwatch carries no third-party dependencies.

**Split search is exhaustive but bounded.** Every candidate threshold is
evaluated for every feature at each node, which is O(features x rows) per node.
For a few thousand rows and a few dozen features that is fast enough, and it is
exact - there is no binning or approximate-histogram step to get wrong.

**Feature subsampling happens once, at fit time.** :func:`_build_tree` draws
its candidate feature subset from a seeded generator as it descends, so
prediction is a plain traversal with no randomness at all. That keeps
inference deterministic and reproducible regardless of how many rows are
scored or in what order.
"""

import math
from collections import Counter

from .base import Model, register
from .rng import RNG

# Cap on distinct thresholds tried per feature, so a high-cardinality count
# column cannot make a single node quadratic in the number of rows.
MAX_SPLIT_VALUES = 48


def _gini_from_counts(counts, total):
    if total <= 0:
        return 0.0
    impurity = 1.0
    for count in counts:
        p = count / total
        impurity -= p * p
    return impurity


def _label_counts(labels):
    counter = Counter(labels)
    return counter.get(1, 0), counter.get(0, 0)


def _gini(labels):
    return _gini_from_counts(_label_counts(labels), len(labels))


def _leaf_value(labels):
    """Majority class, breaking ties toward malicious.

    Ties resolve to 1 deliberately: in threat detection a false negative
    (missing an active intrusion) costs far more than a false positive (one
    extra alert an analyst discards).
    """
    positives, negatives = _label_counts(labels)
    return 1 if positives >= negatives else 0


def _candidate_thresholds(values, limit=MAX_SPLIT_VALUES):
    """Distinct midpoints to split on.

    A constant feature offers no split. When a feature has more distinct
    values than ``limit``, evenly spaced samples are taken and midpoints taken
    between neighbours - an approximation that is immaterial in practice and
    bounded in cost.
    """
    unique = sorted(set(values))
    if len(unique) > limit:
        step = len(unique) / float(limit)
        unique = sorted({unique[int(i * step)] for i in range(limit)})
    if len(unique) < 2:
        return []
    return [(a + b) / 2.0 for a, b in zip(unique, unique[1:])]


class Node:
    """A CART node: either a split on one feature, or a leaf."""

    __slots__ = ("feature", "threshold", "left", "right", "value", "impurity",
                 "n_samples", "n_positive")

    def __init__(self, feature=None, threshold=None, left=None, right=None,
                 value=None, impurity=0.0, n_samples=0, n_positive=0):
        self.feature = feature
        self.threshold = threshold
        self.left = left
        self.right = right
        self.value = value
        self.impurity = impurity
        self.n_samples = n_samples
        self.n_positive = n_positive

    @property
    def is_leaf(self):
        return self.feature is None

    def predict(self, row):
        node = self
        while not node.is_leaf:
            node = (node.left if row[node.feature] <= node.threshold
                    else node.right)
        return node.value

    def to_dict(self):
        return {
            "feature": self.feature, "threshold": self.threshold,
            "value": self.value, "impurity": round(self.impurity, 6),
            "n_samples": self.n_samples, "n_positive": self.n_positive,
            "left": None if self.left is None else self.left.to_dict(),
            "right": None if self.right is None else self.right.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload):
        if payload is None:
            return None
        return cls(feature=payload["feature"], threshold=payload["threshold"],
                   value=payload["value"],
                   impurity=payload.get("impurity", 0.0),
                   n_samples=payload.get("n_samples", 0),
                   n_positive=payload.get("n_positive", 0),
                   left=cls.from_dict(payload.get("left")),
                   right=cls.from_dict(payload.get("right")))


def _build_tree(X, y, indices, n_features, depth, max_depth, min_samples_leaf,
                min_samples_split, rng, feature_pool):
    """Recursively build a CART tree over the rows named in ``indices``."""
    labels = [y[i] for i in indices]
    n_samples = len(indices)
    positives, negatives = _label_counts(labels)
    impurity = _gini_from_counts((positives, negatives), n_samples)
    node = Node(impurity=impurity, n_samples=n_samples, n_positive=positives)

    too_deep = max_depth is not None and depth >= max_depth
    if (too_deep or impurity <= 0.0 or n_samples < min_samples_split
            or positives == 0 or negatives == 0):
        node.value = _leaf_value(labels)
        return node

    if feature_pool < n_features:
        pool = rng.sample(range(n_features), feature_pool)
    else:
        pool = range(n_features)

    best = None
    for feature in pool:
        column = [X[i][feature] for i in indices]
        for threshold in _candidate_thresholds(column):
            left = [i for i, v in zip(indices, column) if v <= threshold]
            right = [i for i, v in zip(indices, column) if v > threshold]
            if len(left) < min_samples_leaf or len(right) < min_samples_leaf:
                continue
            lp, ln = _label_counts([y[i] for i in left])
            rp, rn = _label_counts([y[i] for i in right])
            cost = (_gini_from_counts((lp, ln), len(left)) * len(left) +
                    _gini_from_counts((rp, rn), len(right)) * len(right))
            if best is None or cost < best[0]:
                best = (cost, feature, threshold, left, right)

    if best is None:
        node.value = _leaf_value(labels)
        return node

    _, feature, threshold, left, right = best
    node.feature = feature
    node.threshold = threshold
    node.left = _build_tree(X, y, left, n_features, depth + 1, max_depth,
                            min_samples_leaf, min_samples_split, rng,
                            feature_pool)
    node.right = _build_tree(X, y, right, n_features, depth + 1, max_depth,
                             min_samples_leaf, min_samples_split, rng,
                             feature_pool)
    return node


def _descend(node, row):
    path = []
    while not node.is_leaf:
        went_left = row[node.feature] <= node.threshold
        path.append((node.feature, node.threshold, went_left))
        node = node.left if went_left else node.right
    return node, path


@register
class DecisionTreeClassifier(Model):
    """A single CART binary classifier, kept interpretable by design.

    :param max_depth: maximum depth; ``None`` grows until every leaf is pure.
    :param min_samples_leaf: smallest permitted leaf.
    :param min_samples_split: a node smaller than this becomes a leaf.
    :param feature_pool: features considered per split; ``None`` means all.
    """

    name = "decision-tree"
    needs_scaling = False
    probabilistic = True

    def __init__(self, max_depth=6, min_samples_leaf=1, min_samples_split=2,
                 feature_pool=None, seed=0, feature_names=None, **kwargs):
        super().__init__(feature_names=feature_names,
                         params={"max_depth": max_depth,
                                 "min_samples_leaf": min_samples_leaf,
                                 "min_samples_split": min_samples_split,
                                 "feature_pool": feature_pool, "seed": seed})
        self.max_depth = max_depth
        self.min_samples_leaf = min_samples_leaf
        self.min_samples_split = min_samples_split
        self.feature_pool = feature_pool
        self.seed = seed
        self.root_ = None

    def fit(self, X, y):
        X, y = self._prepare_fit(X, y)
        self.root_ = _build_tree(
            X, y, list(range(len(X))), self.n_features, 0, self.max_depth,
            self.min_samples_leaf, self.min_samples_split, RNG(self.seed),
            self.feature_pool or self.n_features)
        self.fitted = True
        return self

    def _require_fitted(self):
        if not self.fitted or self.root_ is None:
            raise RuntimeError(f"{self.name} has not been fitted yet")

    def decision_function(self, X):
        self._require_fitted()
        return [1.0 if self.root_.predict(row) else -1.0
                for row in self._apply_scaler(X)]

    def predict_proba(self, X):
        """Leaf class distribution, so trees can share the ROC scoring code."""
        self._require_fitted()
        out = []
        for row in self._apply_scaler(X):
            leaf, _ = _descend(self.root_, row)
            p = leaf.n_positive / (leaf.n_samples or 1)
            out.append([1.0 - p, p])
        return out

    def depth(self):
        return _node_depth(self.root_)

    def n_leaves(self):
        return len(_collect_leaves(self.root_, []))

    def to_dict(self):
        payload = super().to_dict()
        payload["root"] = None if self.root_ is None else self.root_.to_dict()
        return payload

    def load_state(self, payload):
        self.root_ = Node.from_dict(payload.get("root"))
        return self


def _node_depth(node):
    if node is None or node.is_leaf:
        return 0
    return 1 + max(_node_depth(node.left), _node_depth(node.right))


def _collect_leaves(node, out):
    if node is None:
        return out
    if node.is_leaf:
        out.append(node)
        return out
    _collect_leaves(node.left, out)
    _collect_leaves(node.right, out)
    return out


def _feature_budget(max_features, n_features):
    if max_features in ("sqrt", None):
        return max(1, int(round(math.sqrt(n_features))))
    if max_features == "log2":
        return max(1, int(round(math.log2(n_features)))) if n_features > 1 \
            else 1
    if isinstance(max_features, float) and 0.0 < max_features <= 1.0:
        return max(1, int(round(max_features * n_features)))
    return max(1, min(int(max_features), n_features))


@register
class RandomForestClassifier(Model):
    """Bagged CART trees with per-split feature subsampling.

    Averaging decorrelated trees is the variance reduction the paper credits
    for Random Forest's edge over the single-model baselines. Each tree is
    grown on a bootstrap resample of the rows and a random feature subset at
    every split; leaf class distributions are averaged across the ensemble.
    """

    name = "random-forest"
    needs_scaling = False
    probabilistic = True

    def __init__(self, n_estimators=25, max_depth=8, min_samples_leaf=1,
                 max_features="sqrt", seed=42, feature_names=None, **kwargs):
        super().__init__(feature_names=feature_names,
                         params={"n_estimators": n_estimators,
                                 "max_depth": max_depth,
                                 "min_samples_leaf": min_samples_leaf,
                                 "max_features": max_features, "seed": seed})
        self.n_estimators = max(1, n_estimators)
        self.max_depth = max_depth
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.seed = seed
        self.estimators_ = []
        self.oob_ = None

    def fit(self, X, y):
        X, y = self._prepare_fit(X, y)
        n = len(X)
        pool = _feature_budget(self.max_features, self.n_features)
        self.estimators_ = []
        for index in range(self.n_estimators):
            rng = RNG(self.seed * 1000003 + index)
            sample = [rng.randint(0, n - 1) for _ in range(n)]
            tree = DecisionTreeClassifier(
                max_depth=self.max_depth,
                min_samples_leaf=self.min_samples_leaf,
                feature_pool=pool, seed=self.seed * 31 + index,
                feature_names=self.feature_names)
            tree.fit([X[i] for i in sample], [y[i] for i in sample])
            self.estimators_.append(tree)
        self.oob_ = self._oob_score(X, y)
        self.fitted = True
        return self

    def _oob_score(self, X, y):
        """Out-of-bag accuracy, the forest's own generalisation estimate.

        Each row is scored only by the trees whose bootstrap sample missed it,
        so the estimate never sees a row those trees were fitted on.
        """
        n = len(X)
        in_bag = [[] for _ in range(n)]
        for index, rng in enumerate(self._bootstrap_seeds(n)):
            for position in rng:
                in_bag[position].append(index)
        correct = scored = 0
        for position in range(n):
            voters = [self.estimators_[i] for i in in_bag[position]]
            if not voters:
                continue
            positive = math.fsum(
                tree.predict_proba([X[position]])[0][1] for tree in voters)
            predicted = 1 if positive / len(voters) >= 0.5 else 0
            correct += int(predicted == y[position])
            scored += 1
        return (correct / scored) if scored else None

    def _bootstrap_seeds(self, n):
        for index in range(self.n_estimators):
            rng = RNG(self.seed * 1000003 + index)
            yield [rng.randint(0, n - 1) for _ in range(n)]

    def predict_proba(self, X):
        if not self.fitted:
            raise RuntimeError(f"{self.name} has not been fitted yet")
        rows = self._apply_scaler(X)
        totals = [0.0] * len(rows)
        for tree in self.estimators_:
            for position, p in enumerate(tree.predict_proba(rows)):
                totals[position] += p[1]
        count = float(len(self.estimators_)) or 1.0
        return [[1.0 - t / count, t / count] for t in totals]

    def to_dict(self):
        payload = super().to_dict()
        payload["estimators"] = [tree.to_dict() for tree in self.estimators_]
        payload["oob"] = self.oob_
        return payload

    def load_state(self, payload):
        self.estimators_ = [DecisionTreeClassifier.from_dict(tree)
                            for tree in payload.get("estimators", [])]
        self.oob_ = payload.get("oob")
        return self


@register
class GradientBoostingClassifier(Model):
    """Boosted stumps/trees fitted sequentially to the log-odds residual.

    Each weak learner is fitted to the gradient of the loss with respect to the
    current ensemble's raw score, then the ensemble score is updated by
    ``learning_rate * leaf_value``. Fitted on soft labels (the current
    probability) rather than hard 0/1, which is what makes boosting outperform
    bagging on this kind of problem.
    """

    name = "gradient-boosting"
    needs_scaling = False
    probabilistic = True

    def __init__(self, n_estimators=50, learning_rate=0.1, max_depth=3,
                 seed=42, feature_names=None, **kwargs):
        super().__init__(feature_names=feature_names,
                         params={"n_estimators": n_estimators,
                                 "learning_rate": learning_rate,
                                 "max_depth": max_depth, "seed": seed})
        self.n_estimators = max(1, n_estimators)
        self.learning_rate = learning_rate
        self.max_depth = max_depth
        self.seed = seed
        self.trees_ = []
        self.init_score_ = 0.0
        self.train_loss_ = []

    @staticmethod
    def _sigmoid(z):
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        exp_z = math.exp(z)
        return exp_z / (1.0 + exp_z)

    def fit(self, X, y):
        X, y = self._prepare_fit(X, y)
        positives = sum(1 for v in y if v == 1)
        rate = positives / len(y)
        self.init_score_ = math.log(rate / (1.0 - rate)) \
            if 0.0 < rate < 1.0 else 0.0
        self.trees_ = []
        self.train_loss_ = []
        raw = [self.init_score_] * len(X)
        for index in range(self.n_estimators):
            probs = [self._sigmoid(v) for v in raw]
            residuals = [p - t for p, t in zip(probs, y)]
            tree = DecisionTreeClassifier(
                max_depth=self.max_depth, min_samples_leaf=1,
                feature_names=self.feature_names)
            tree.fit(X, [1 if r > 0 else 0 for r in residuals])
            for position, row in enumerate(X):
                leaf, _ = _descend(tree.root_, row)
                value = leaf.n_positive / (leaf.n_samples or 1)
                raw[position] += self.learning_rate * (2.0 * value - 1.0)
            self.trees_.append(tree)
            self.train_loss_.append(math.fsum(
                -(t * math.log(max(1e-15, self._sigmoid(r))) +
                  (1 - t) * math.log(max(1e-15, 1 - self._sigmoid(r))))
                for r, t in zip(raw, y)) / len(y))
        self.fitted = True
        return self

    def decision_function(self, X):
        if not self.fitted:
            raise RuntimeError(f"{self.name} has not been fitted yet")
        rows = self._apply_scaler(X)
        out = []
        for row in rows:
            score = self.init_score_
            for tree in self.trees_:
                leaf, _ = _descend(tree.root_, row)
                value = leaf.n_positive / (leaf.n_samples or 1)
                score += self.learning_rate * (2.0 * value - 1.0)
            out.append(score)
        return out

    def to_dict(self):
        payload = super().to_dict()
        payload["trees"] = [tree.to_dict() for tree in self.trees_]
        payload["init_score"] = self.init_score_
        payload["train_loss"] = self.train_loss_
        return payload

    def load_state(self, payload):
        self.trees_ = [DecisionTreeClassifier.from_dict(tree)
                       for tree in payload.get("trees", [])]
        self.init_score_ = payload.get("init_score", 0.0)
        self.train_loss_ = payload.get("train_loss", [])
        return self


__all__ = ["Node", "DecisionTreeClassifier", "RandomForestClassifier",
           "GradientBoostingClassifier"]
