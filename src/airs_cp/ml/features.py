"""
Feature Extraction for ML Models

Extracts numerical features from text for anomaly detection
and injection classification.
"""

import re
from dataclasses import dataclass
from typing import Any, Optional

import numpy as np


@dataclass
class TextFeatures:
    """Features extracted from text for ML models."""
    # Length features
    char_count: int = 0
    word_count: int = 0
    line_count: int = 0
    avg_word_length: float = 0.0
    
    # Character composition
    uppercase_ratio: float = 0.0
    digit_ratio: float = 0.0
    special_char_ratio: float = 0.0
    whitespace_ratio: float = 0.0
    
    # Lexical features
    unique_word_ratio: float = 0.0
    lexical_diversity: float = 0.0
    
    # Pattern indicators (binary)
    has_code_block: int = 0
    has_url: int = 0
    has_email: int = 0
    has_system_keywords: int = 0
    has_ignore_pattern: int = 0
    has_jailbreak_pattern: int = 0
    has_role_switch: int = 0
    
    # Injection indicators
    injection_keyword_count: int = 0
    instruction_override_score: float = 0.0
    
    # Entropy
    char_entropy: float = 0.0
    
    def to_array(self) -> np.ndarray:
        """Convert features to numpy array."""
        return np.array([
            self.char_count,
            self.word_count,
            self.line_count,
            self.avg_word_length,
            self.uppercase_ratio,
            self.digit_ratio,
            self.special_char_ratio,
            self.whitespace_ratio,
            self.unique_word_ratio,
            self.lexical_diversity,
            self.has_code_block,
            self.has_url,
            self.has_email,
            self.has_system_keywords,
            self.has_ignore_pattern,
            self.has_jailbreak_pattern,
            self.has_role_switch,
            self.injection_keyword_count,
            self.instruction_override_score,
            self.char_entropy,
        ], dtype=np.float32)
    
    @staticmethod
    def feature_names() -> list[str]:
        """Get feature names for explainability."""
        return [
            "char_count",
            "word_count",
            "line_count",
            "avg_word_length",
            "uppercase_ratio",
            "digit_ratio",
            "special_char_ratio",
            "whitespace_ratio",
            "unique_word_ratio",
            "lexical_diversity",
            "has_code_block",
            "has_url",
            "has_email",
            "has_system_keywords",
            "has_ignore_pattern",
            "has_jailbreak_pattern",
            "has_role_switch",
            "injection_keyword_count",
            "instruction_override_score",
            "char_entropy",
        ]


# Patterns for detection
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior|above)",
    r"forget\s+(everything|all)",
    r"you\s+are\s+now\s+",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*",
    r"<\|?system\|?>",
    r"\[system\]",
    r"jailbreak",
    r"DAN\s*mode",
    r"developer\s+mode",
    r"do\s+anything\s+now",
    r"pretend\s+(you\s+are|to\s+be)",
    r"act\s+as\s+(if|a)",
    r"roleplay\s+as",
]

SYSTEM_KEYWORDS = [
    "system prompt", "system message", "instructions",
    "guidelines", "rules", "constraints", "restrictions",
    "confidential", "secret", "hidden", "internal",
]

ROLE_SWITCH_PATTERNS = [
    r"you\s+are\s+(?:now\s+)?(?:a|an|the)\s+",
    r"from\s+now\s+on\s*,?\s*you",
    r"switch\s+(?:to|into)\s+",
    r"enter\s+(?:\w+\s+)?mode",
]

URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
CODE_BLOCK_PATTERN = re.compile(r'```[\s\S]*?```|`[^`]+`')


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if not text:
        return 0.0
    
    # Count character frequencies
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * np.log2(prob)
    
    return entropy


def extract_features(text: str) -> TextFeatures:
    """
    Extract features from text for ML models.
    
    Args:
        text: Input text to analyze.
        
    Returns:
        TextFeatures object with extracted features.
    """
    if not text:
        return TextFeatures()
    
    features = TextFeatures()
    
    # Length features
    features.char_count = len(text)
    words = text.split()
    features.word_count = len(words)
    features.line_count = text.count('\n') + 1
    features.avg_word_length = (
        sum(len(w) for w in words) / len(words) if words else 0
    )
    
    # Character composition
    if features.char_count > 0:
        features.uppercase_ratio = sum(1 for c in text if c.isupper()) / features.char_count
        features.digit_ratio = sum(1 for c in text if c.isdigit()) / features.char_count
        features.special_char_ratio = sum(
            1 for c in text if not c.isalnum() and not c.isspace()
        ) / features.char_count
        features.whitespace_ratio = sum(1 for c in text if c.isspace()) / features.char_count
    
    # Lexical features
    if features.word_count > 0:
        unique_words = set(w.lower() for w in words)
        features.unique_word_ratio = len(unique_words) / features.word_count
        features.lexical_diversity = len(unique_words) / (1 + np.log(features.word_count))
    
    # Pattern detection
    text_lower = text.lower()
    
    features.has_code_block = 1 if CODE_BLOCK_PATTERN.search(text) else 0
    features.has_url = 1 if URL_PATTERN.search(text) else 0
    features.has_email = 1 if EMAIL_PATTERN.search(text) else 0
    
    # System keywords
    features.has_system_keywords = 1 if any(kw in text_lower for kw in SYSTEM_KEYWORDS) else 0
    
    # Injection patterns
    ignore_count = 0
    jailbreak_count = 0
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            if "ignore" in pattern or "disregard" in pattern or "forget" in pattern:
                ignore_count += 1
            else:
                jailbreak_count += 1
    
    features.has_ignore_pattern = 1 if ignore_count > 0 else 0
    features.has_jailbreak_pattern = 1 if jailbreak_count > 0 else 0
    features.injection_keyword_count = ignore_count + jailbreak_count
    
    # Role switch patterns
    role_switch_count = sum(
        1 for pattern in ROLE_SWITCH_PATTERNS
        if re.search(pattern, text_lower)
    )
    features.has_role_switch = 1 if role_switch_count > 0 else 0
    
    # Instruction override score (heuristic)
    features.instruction_override_score = min(1.0, (
        features.has_ignore_pattern * 0.4 +
        features.has_jailbreak_pattern * 0.3 +
        features.has_role_switch * 0.2 +
        features.has_system_keywords * 0.1
    ))
    
    # Entropy
    features.char_entropy = calculate_entropy(text)
    
    return features


def extract_features_batch(texts: list[str]) -> np.ndarray:
    """
    Extract features from multiple texts.
    
    Args:
        texts: List of input texts.
        
    Returns:
        2D numpy array of shape (n_texts, n_features).
    """
    return np.vstack([extract_features(text).to_array() for text in texts])


class FeatureExtractor:
    """
    Feature extractor with optional normalization.
    
    Provides consistent feature extraction across training
    and inference with optional feature scaling.
    """
    
    def __init__(self):
        """Initialize the feature extractor."""
        self.mean_: Optional[np.ndarray] = None
        self.std_: Optional[np.ndarray] = None
        self.fitted = False
    
    def fit(self, texts: list[str]) -> "FeatureExtractor":
        """
        Fit the extractor on training data.
        
        Computes mean and std for normalization.
        
        Args:
            texts: Training texts.
            
        Returns:
            Self for chaining.
        """
        features = extract_features_batch(texts)
        self.mean_ = features.mean(axis=0)
        self.std_ = features.std(axis=0)
        # Avoid division by zero
        self.std_[self.std_ == 0] = 1.0
        self.fitted = True
        return self
    
    def transform(self, texts: list[str], normalize: bool = True) -> np.ndarray:
        """
        Extract and optionally normalize features.
        
        Args:
            texts: Texts to transform.
            normalize: Whether to normalize features.
            
        Returns:
            Feature array.
        """
        features = extract_features_batch(texts)
        
        if normalize and self.fitted:
            features = (features - self.mean_) / self.std_
        
        return features
    
    def fit_transform(self, texts: list[str], normalize: bool = True) -> np.ndarray:
        """Fit and transform in one step."""
        self.fit(texts)
        return self.transform(texts, normalize)
    
    def extract_single(self, text: str, normalize: bool = True) -> np.ndarray:
        """Extract features for a single text."""
        return self.transform([text], normalize)[0]
