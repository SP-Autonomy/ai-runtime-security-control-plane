"""
SHAP Explainer for ML Decisions

Provides feature-level explanations for ML model predictions
using SHAP (SHapley Additive exPlanations).
"""

from typing import Any, Optional

import numpy as np

from airs_cp.ml.features import TextFeatures, extract_features
from airs_cp.store.models import Explanation, ExplanationType


class SHAPExplainer:
    """
    SHAP-based explainer for ML security decisions.
    
    Provides feature attribution for classification and
    anomaly detection results.
    """
    
    def __init__(self):
        """Initialize the SHAP explainer."""
        self._shap_available = False
        try:
            import shap
            self._shap_available = True
            self._shap = shap
        except ImportError:
            pass
    
    def explain_classifier(
        self,
        classifier,
        text: str,
        use_approximation: bool = True,
    ) -> dict[str, Any]:
        """
        Generate SHAP explanation for classifier prediction.
        
        Args:
            classifier: Trained InjectionClassifier.
            text: Input text.
            use_approximation: Use coefficient-based approximation if SHAP unavailable.
            
        Returns:
            Explanation with feature contributions.
        """
        # Get prediction
        prediction = classifier.predict(text)
        features = extract_features(text)
        feature_values = features.to_array()
        feature_names = TextFeatures.feature_names()
        
        if self._shap_available and not use_approximation:
            # Full SHAP computation
            try:
                X = classifier.feature_extractor.transform([text], normalize=False)
                X_scaled = classifier.scaler.transform(X)
                
                explainer = self._shap.LinearExplainer(
                    classifier.model,
                    X_scaled,
                    feature_perturbation="interventional"
                )
                shap_values = explainer.shap_values(X_scaled)
                
                contributions = []
                for name, value, shap_val in zip(feature_names, feature_values, shap_values[0]):
                    contributions.append({
                        "name": name,
                        "value": float(value),
                        "shap_value": float(shap_val),
                        "contribution": float(shap_val),
                    })
                
                # Sort by absolute contribution
                contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
                
                return {
                    "type": "shap",
                    "method": "linear_explainer",
                    "model": "injection_classifier",
                    "prediction": prediction["prediction"],
                    "confidence": prediction["confidence"],
                    "features": contributions[:10],  # Top 10
                    "baseline": float(classifier.model.intercept_[0]),
                }
            except Exception:
                pass
        
        # Coefficient-based approximation (faster, always available)
        coefficients = classifier.model.coef_[0]
        X = classifier.feature_extractor.transform([text], normalize=False)
        X_scaled = classifier.scaler.transform(X)[0]
        
        contributions = []
        for name, value, coef, scaled_val in zip(
            feature_names, feature_values, coefficients, X_scaled
        ):
            contribution = coef * scaled_val
            contributions.append({
                "name": name,
                "value": float(value),
                "coefficient": float(coef),
                "scaled_value": float(scaled_val),
                "contribution": float(contribution),
            })
        
        contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
        
        return {
            "type": "shap",
            "method": "coefficient_approximation",
            "model": "injection_classifier",
            "prediction": prediction["prediction"],
            "confidence": prediction["confidence"],
            "features": contributions[:10],
            "baseline": float(classifier.model.intercept_[0]),
        }
    
    def explain_anomaly(
        self,
        detector,
        text: str,
    ) -> dict[str, Any]:
        """
        Generate explanation for anomaly detection result.
        
        Args:
            detector: Trained AnomalyDetector.
            text: Input text.
            
        Returns:
            Explanation with feature analysis.
        """
        # Get prediction
        prediction = detector.predict(text)
        features = extract_features(text)
        feature_values = features.to_array()
        feature_names = TextFeatures.feature_names()
        
        # For IsolationForest, we analyze feature deviations from training mean
        X = detector.feature_extractor.transform([text], normalize=True)
        deviations = np.abs(X[0])  # Z-scores after normalization
        
        contributions = []
        for name, value, deviation in zip(feature_names, feature_values, deviations):
            contributions.append({
                "name": name,
                "value": float(value),
                "deviation": float(deviation),
                "is_unusual": bool(deviation > 2.0),  # More than 2 std devs
            })
        
        # Sort by deviation
        contributions.sort(key=lambda x: x["deviation"], reverse=True)
        
        # Find most unusual features
        unusual_features = [c for c in contributions if c["is_unusual"]]
        
        return {
            "type": "shap",
            "method": "deviation_analysis",
            "model": "anomaly_detector",
            "is_anomaly": prediction["is_anomaly"],
            "anomaly_score": prediction["anomaly_score"],
            "raw_score": prediction["raw_score"],
            "features": contributions[:10],
            "unusual_features": unusual_features[:5],
            "interpretation": self._interpret_anomaly(unusual_features),
        }
    
    def _interpret_anomaly(self, unusual_features: list[dict]) -> str:
        """Generate human-readable interpretation of anomaly."""
        if not unusual_features:
            return "No significantly unusual features detected."
        
        feature_names = [f["name"] for f in unusual_features[:3]]
        
        interpretations = {
            "char_count": "unusual message length",
            "word_count": "unusual word count",
            "uppercase_ratio": "abnormal capitalization",
            "special_char_ratio": "unusual special character usage",
            "has_ignore_pattern": "instruction override patterns",
            "has_jailbreak_pattern": "jailbreak-related content",
            "has_role_switch": "role manipulation attempt",
            "injection_keyword_count": "injection-related keywords",
            "instruction_override_score": "high instruction override indicators",
            "char_entropy": "unusual text entropy",
        }
        
        reasons = []
        for name in feature_names:
            if name in interpretations:
                reasons.append(interpretations[name])
            else:
                reasons.append(f"unusual {name.replace('_', ' ')}")
        
        return f"Anomaly detected due to: {', '.join(reasons)}."
    
    def to_explanation(
        self,
        shap_result: dict[str, Any],
        detection_id: Optional[str] = None,
    ) -> Explanation:
        """
        Create Explanation object from SHAP result.
        
        Args:
            shap_result: Result from explain_* method.
            detection_id: Associated detection ID.
            
        Returns:
            Explanation object.
        """
        return Explanation(
            detection_id=detection_id,
            explanation_type=ExplanationType.SHAP,
            content=shap_result,
        )


# Global explainer instance
_explainer: Optional[SHAPExplainer] = None


def get_shap_explainer() -> SHAPExplainer:
    """Get the global SHAP explainer instance."""
    global _explainer
    if _explainer is None:
        _explainer = SHAPExplainer()
    return _explainer
