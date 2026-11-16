"""Machine learning models for Nightwatch.

Includes feature engineering, logistic regression, linear SVM, decision tree,
random forest, and gradient boosting classifiers - all implemented from scratch
with no third-party dependencies.
"""

from .base import Model, register, load_model
from .features import FEATURES, FEATURE_COUNT, vectorize, row, describe
from .linalg import entropy, log1p_scaled, sigmoid, StandardScaler, MinMaxScaler
from .linear import LogisticRegression, LinearSVC
from .tree import Node, DecisionTreeClassifier, RandomForestClassifier, GradientBoostingClassifier
from .rng import RNG, shuffle, kfold, stratified_folds

__all__ = [
    "Model", "register", "load_model",
    "FEATURES", "FEATURE_COUNT", "vectorize", "row", "describe",
    "entropy", "log1p_scaled", "sigmoid", "StandardScaler", "MinMaxScaler",
    "LogisticRegression", "LinearSVC",
    "Node", "DecisionTreeClassifier", "RandomForestClassifier", "GradientBoostingClassifier",
    "RNG", "shuffle", "kfold", "stratified_folds",
]
