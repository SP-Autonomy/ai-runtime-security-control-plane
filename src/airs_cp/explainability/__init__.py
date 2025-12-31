"""
Explainability Module

Provides human-readable explanations for security decisions:
- SHAP explanations for ML models
- LLM-generated narratives for complex decisions
- Template-based explanations for simple cases
"""

from airs_cp.explainability.shap_explainer import (
    SHAPExplainer,
    get_shap_explainer,
)
from airs_cp.explainability.narrative import (
    NarrativeGenerator,
    get_narrative_generator,
)

__all__ = [
    "SHAPExplainer",
    "get_shap_explainer",
    "NarrativeGenerator",
    "get_narrative_generator",
]
