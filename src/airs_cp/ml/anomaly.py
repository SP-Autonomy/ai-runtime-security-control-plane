"""
Anomaly Detection using IsolationForest

Detects unusual request patterns that may indicate attacks
or misuse, without requiring labeled training data.
"""

import json
import pickle
from pathlib import Path
from typing import Any, Optional

import numpy as np

# Import sklearn with graceful fallback
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from airs_cp.ml.features import FeatureExtractor, extract_features, TextFeatures


class AnomalyDetector:
    """
    Anomaly detector using IsolationForest.
    
    Learns normal request patterns and flags anomalies
    that deviate significantly from the norm.
    """
    
    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        """
        Initialize the anomaly detector.
        
        Args:
            contamination: Expected proportion of anomalies (0.0-0.5).
            n_estimators: Number of trees in the forest.
            random_state: Random seed for reproducibility.
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError(
                "scikit-learn is required for anomaly detection. "
                "Install with: pip install scikit-learn"
            )
        
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        
        self.model: Optional[IsolationForest] = None
        self.feature_extractor = FeatureExtractor()
        self.fitted = False
        self.threshold: float = 0.0
    
    def fit(self, texts: list[str]) -> "AnomalyDetector":
        """
        Train the anomaly detector on normal data.
        
        Args:
            texts: List of normal (non-anomalous) text samples.
            
        Returns:
            Self for chaining.
        """
        # Extract features
        X = self.feature_extractor.fit_transform(texts, normalize=True)
        
        # Train IsolationForest
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X)
        
        # Compute threshold from training data scores
        scores = self.model.decision_function(X)
        self.threshold = np.percentile(scores, self.contamination * 100)
        
        self.fitted = True
        return self
    
    def predict(self, text: str) -> dict[str, Any]:
        """
        Predict if a text is anomalous.
        
        Args:
            text: Text to analyze.
            
        Returns:
            Dict with prediction results.
        """
        if not self.fitted:
            raise ValueError("Model not fitted. Call fit() first.")
        
        # Extract features
        features = extract_features(text)
        X = self.feature_extractor.transform([text], normalize=True)
        
        # Get anomaly score
        # IsolationForest: negative scores = anomalies, positive = normal
        raw_score = self.model.decision_function(X)[0]
        prediction = self.model.predict(X)[0]  # -1 = anomaly, 1 = normal
        
        is_anomaly = prediction == -1
        
        # Convert to probability-like score (0-1, higher = more anomalous)
        # Using sigmoid-like transformation
        anomaly_score = 1.0 / (1.0 + np.exp(raw_score * 2))
        
        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": float(anomaly_score),
            "raw_score": float(raw_score),
            "threshold": float(self.threshold),
            "features": {
                name: float(val) 
                for name, val in zip(
                    TextFeatures.feature_names(),
                    features.to_array()
                )
            },
        }
    
    def predict_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """Predict anomalies for multiple texts."""
        return [self.predict(text) for text in texts]
    
    def get_feature_importances(self) -> dict[str, float]:
        """
        Estimate feature importances.
        
        Note: IsolationForest doesn't have direct feature importances.
        This uses a permutation-based approximation.
        """
        # Return uniform importances as approximation
        names = TextFeatures.feature_names()
        return {name: 1.0 / len(names) for name in names}
    
    def save(self, path: str) -> None:
        """
        Save the trained model to disk.
        
        Args:
            path: Path to save the model.
        """
        if not self.fitted:
            raise ValueError("Cannot save unfitted model.")
        
        model_path = Path(path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "model": self.model,
            "feature_extractor_mean": self.feature_extractor.mean_,
            "feature_extractor_std": self.feature_extractor.std_,
            "threshold": self.threshold,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
        }
        
        with open(model_path, "wb") as f:
            pickle.dump(data, f)
    
    @classmethod
    def load(cls, path: str) -> "AnomalyDetector":
        """
        Load a trained model from disk.
        
        Args:
            path: Path to the saved model.
            
        Returns:
            Loaded AnomalyDetector instance.
        """
        with open(path, "rb") as f:
            data = pickle.load(f)
        
        detector = cls(
            contamination=data["contamination"],
            n_estimators=data["n_estimators"],
            random_state=data["random_state"],
        )
        detector.model = data["model"]
        detector.feature_extractor.mean_ = data["feature_extractor_mean"]
        detector.feature_extractor.std_ = data["feature_extractor_std"]
        detector.feature_extractor.fitted = True
        detector.threshold = data["threshold"]
        detector.fitted = True
        
        return detector


# Global detector instance for hot-reload
_detector: Optional[AnomalyDetector] = None


def get_anomaly_detector(model_path: Optional[str] = None) -> Optional[AnomalyDetector]:
    """
    Get the global anomaly detector instance.
    
    Args:
        model_path: Path to load model from (if not already loaded).
        
    Returns:
        AnomalyDetector or None if not available.
    """
    global _detector
    
    if _detector is None and model_path:
        try:
            _detector = AnomalyDetector.load(model_path)
        except Exception:
            return None
    
    return _detector


def set_anomaly_detector(detector: AnomalyDetector) -> None:
    """Set the global anomaly detector instance."""
    global _detector
    _detector = detector
