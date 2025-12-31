"""
Machine Learning Module

Provides ML-based security detection including:
- Anomaly detection (IsolationForest)
- Injection classification (Logistic Regression)
- Feature extraction
- Model training utilities
"""

from airs_cp.ml.features import (
    FeatureExtractor,
    TextFeatures,
    extract_features,
    extract_features_batch,
)
from airs_cp.ml.anomaly import (
    AnomalyDetector,
    get_anomaly_detector,
    set_anomaly_detector,
)
from airs_cp.ml.classifier import (
    InjectionClassifier,
    get_injection_classifier,
    set_injection_classifier,
)

__all__ = [
    # Feature extraction
    "FeatureExtractor",
    "TextFeatures",
    "extract_features",
    "extract_features_batch",
    # Anomaly detection
    "AnomalyDetector",
    "get_anomaly_detector",
    "set_anomaly_detector",
    # Classification
    "InjectionClassifier",
    "get_injection_classifier",
    "set_injection_classifier",
]
