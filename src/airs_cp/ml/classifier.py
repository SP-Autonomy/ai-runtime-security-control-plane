"""
Injection Classifier using Logistic Regression

Supervised classifier for detecting prompt injection attempts
with high accuracy and interpretable predictions.
"""

import json
import pickle
from pathlib import Path
from typing import Any, Optional

import numpy as np

# Import sklearn with graceful fallback
try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from airs_cp.ml.features import FeatureExtractor, extract_features, TextFeatures


class InjectionClassifier:
    """
    Binary classifier for prompt injection detection.
    
    Uses Logistic Regression for interpretable predictions
    with feature coefficients for explainability.
    """
    
    def __init__(
        self,
        C: float = 1.0,
        max_iter: int = 1000,
        random_state: int = 42,
    ):
        """
        Initialize the classifier.
        
        Args:
            C: Inverse regularization strength.
            max_iter: Maximum iterations for optimization.
            random_state: Random seed for reproducibility.
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError(
                "scikit-learn is required for classification. "
                "Install with: pip install scikit-learn"
            )
        
        self.C = C
        self.max_iter = max_iter
        self.random_state = random_state
        
        self.model: Optional[LogisticRegression] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_extractor = FeatureExtractor()
        self.fitted = False
        self.classes_ = ["benign", "injection"]
        self.cv_scores_: Optional[np.ndarray] = None
    
    def fit(
        self,
        texts: list[str],
        labels: list[int],
        validate: bool = True,
    ) -> "InjectionClassifier":
        """
        Train the classifier.
        
        Args:
            texts: Training texts.
            labels: Binary labels (0=benign, 1=injection).
            validate: Whether to run cross-validation.
            
        Returns:
            Self for chaining.
        """
        # Extract features
        X = self.feature_extractor.fit_transform(texts, normalize=False)
        y = np.array(labels)
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train classifier
        self.model = LogisticRegression(
            C=self.C,
            max_iter=self.max_iter,
            random_state=self.random_state,
            class_weight="balanced",  # Handle imbalanced data
        )
        self.model.fit(X_scaled, y)
        
        # Cross-validation
        if validate and len(texts) >= 10:
            self.cv_scores_ = cross_val_score(
                self.model, X_scaled, y, cv=min(5, len(texts)), scoring="accuracy"
            )
        
        self.fitted = True
        return self
    
    def predict(self, text: str) -> dict[str, Any]:
        """
        Predict if a text contains injection.
        
        Args:
            text: Text to classify.
            
        Returns:
            Dict with prediction results.
        """
        if not self.fitted:
            raise ValueError("Model not fitted. Call fit() first.")
        
        # Extract features
        features = extract_features(text)
        X = self.feature_extractor.transform([text], normalize=False)
        X_scaled = self.scaler.transform(X)
        
        # Get prediction and probability
        prediction = self.model.predict(X_scaled)[0]
        probabilities = self.model.predict_proba(X_scaled)[0]
        
        is_injection = prediction == 1
        confidence = probabilities[1] if is_injection else probabilities[0]
        
        # Get feature contributions
        coefficients = self.model.coef_[0]
        feature_names = TextFeatures.feature_names()
        feature_values = features.to_array()
        
        contributions = []
        for name, coef, val in zip(feature_names, coefficients, feature_values):
            contribution = coef * val
            contributions.append({
                "name": name,
                "value": float(val),
                "coefficient": float(coef),
                "contribution": float(contribution),
            })
        
        # Sort by absolute contribution
        contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
        
        return {
            "is_injection": is_injection,
            "prediction": self.classes_[prediction],
            "confidence": float(confidence),
            "probability_benign": float(probabilities[0]),
            "probability_injection": float(probabilities[1]),
            "top_features": contributions[:5],  # Top 5 contributors
            "all_features": contributions,
        }
    
    def predict_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """Predict for multiple texts."""
        return [self.predict(text) for text in texts]
    
    def get_feature_importances(self) -> dict[str, float]:
        """
        Get feature importances based on coefficients.
        
        Returns:
            Dict mapping feature names to importance scores.
        """
        if not self.fitted:
            raise ValueError("Model not fitted.")
        
        coefficients = np.abs(self.model.coef_[0])
        # Normalize to sum to 1
        importances = coefficients / coefficients.sum()
        
        return dict(zip(TextFeatures.feature_names(), importances))
    
    def get_model_stats(self) -> dict[str, Any]:
        """Get model statistics."""
        if not self.fitted:
            return {"fitted": False}
        
        stats = {
            "fitted": True,
            "n_features": len(TextFeatures.feature_names()),
            "classes": self.classes_,
            "regularization": self.C,
        }
        
        if self.cv_scores_ is not None:
            stats["cv_accuracy_mean"] = float(self.cv_scores_.mean())
            stats["cv_accuracy_std"] = float(self.cv_scores_.std())
        
        return stats
    
    def save(self, path: str) -> None:
        """Save the trained model to disk."""
        if not self.fitted:
            raise ValueError("Cannot save unfitted model.")
        
        model_path = Path(path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_extractor_mean": self.feature_extractor.mean_,
            "feature_extractor_std": self.feature_extractor.std_,
            "C": self.C,
            "max_iter": self.max_iter,
            "random_state": self.random_state,
            "cv_scores": self.cv_scores_,
        }
        
        with open(model_path, "wb") as f:
            pickle.dump(data, f)
    
    @classmethod
    def load(cls, path: str) -> "InjectionClassifier":
        """Load a trained model from disk."""
        with open(path, "rb") as f:
            data = pickle.load(f)
        
        classifier = cls(
            C=data["C"],
            max_iter=data["max_iter"],
            random_state=data["random_state"],
        )
        classifier.model = data["model"]
        classifier.scaler = data["scaler"]
        classifier.feature_extractor.mean_ = data["feature_extractor_mean"]
        classifier.feature_extractor.std_ = data["feature_extractor_std"]
        classifier.feature_extractor.fitted = True
        classifier.cv_scores_ = data.get("cv_scores")
        classifier.fitted = True
        
        return classifier


# Global classifier instance
_classifier: Optional[InjectionClassifier] = None


def get_injection_classifier(model_path: Optional[str] = None) -> Optional[InjectionClassifier]:
    """Get the global injection classifier instance."""
    global _classifier
    
    if _classifier is None and model_path:
        try:
            _classifier = InjectionClassifier.load(model_path)
        except Exception:
            return None
    
    return _classifier


def set_injection_classifier(classifier: InjectionClassifier) -> None:
    """Set the global injection classifier instance."""
    global _classifier
    _classifier = classifier
