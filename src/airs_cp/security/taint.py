"""
Taint Tracking Engine

Provides data provenance and lineage tracking across
agent workflows. Tracks where data came from and where it flows.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

from airs_cp.store.models import (
    TaintEdge,
    TaintLabel,
    TaintSensitivity,
    TaintSourceType,
    generate_id,
    now_iso,
)


@dataclass
class TaintedData:
    """Container for data with taint information."""
    content: str
    taints: list[TaintLabel] = field(default_factory=list)
    content_hash: Optional[str] = None
    
    def __post_init__(self):
        if self.content_hash is None:
            self.content_hash = self._compute_hash()
    
    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(self.content.encode()).hexdigest()[:16]
    
    @property
    def max_sensitivity(self) -> TaintSensitivity:
        """Get the maximum sensitivity level from all taints."""
        if not self.taints:
            return TaintSensitivity.PUBLIC
        
        order = [
            TaintSensitivity.PUBLIC,
            TaintSensitivity.INTERNAL,
            TaintSensitivity.CONFIDENTIAL,
            TaintSensitivity.RESTRICTED,
        ]
        max_idx = 0
        for taint in self.taints:
            idx = order.index(taint.sensitivity)
            max_idx = max(max_idx, idx)
        return order[max_idx]
    
    @property
    def labels(self) -> list[str]:
        """Get all unique taint labels."""
        return list(set(t.label for t in self.taints))
    
    def has_taint(self, label: str) -> bool:
        """Check if data has a specific taint label."""
        return any(t.label == label for t in self.taints)
    
    def has_sensitivity(self, sensitivity: TaintSensitivity) -> bool:
        """Check if data has at least the given sensitivity level."""
        order = [
            TaintSensitivity.PUBLIC,
            TaintSensitivity.INTERNAL,
            TaintSensitivity.CONFIDENTIAL,
            TaintSensitivity.RESTRICTED,
        ]
        target_idx = order.index(sensitivity)
        for taint in self.taints:
            if order.index(taint.sensitivity) >= target_idx:
                return True
        return False


class TaintEngine:
    """
    Engine for taint tracking and propagation.
    
    Implements the taint propagation rules defined in TAINT_SPEC.md.
    """
    
    def __init__(self, store=None):
        """
        Initialize the taint engine.
        
        Args:
            store: Optional EvidenceStore for persistence.
        """
        self.store = store
        self._pending_labels: list[TaintLabel] = []
        self._pending_edges: list[TaintEdge] = []
    
    def create_taint(
        self,
        content: str,
        source_type: TaintSourceType,
        source_id: str,
        sensitivity: TaintSensitivity = TaintSensitivity.PUBLIC,
        label: str = "",
    ) -> TaintedData:
        """
        Create tainted data from a source.
        
        Args:
            content: The data content.
            source_type: Type of data source.
            source_id: Identifier for the source.
            sensitivity: Sensitivity level.
            label: Optional descriptive label.
            
        Returns:
            TaintedData with the taint label.
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        taint = TaintLabel(
            source_type=source_type,
            source_id=source_id,
            sensitivity=sensitivity,
            label=label or source_type.value,
            content_hash=content_hash,
        )
        
        # Persist if store available
        if self.store:
            self.store.create_taint_label(taint)
        else:
            self._pending_labels.append(taint)
        
        return TaintedData(content=content, taints=[taint], content_hash=content_hash)
    
    def propagate(
        self,
        *inputs: TaintedData,
        operation: str = "concatenate",
    ) -> list[TaintLabel]:
        """
        Propagate taints from multiple inputs.
        
        Implements Rule 1 (Concatenation):
        taint(A + B) = taint(A) ∪ taint(B)
        
        Args:
            inputs: Input TaintedData objects.
            operation: Operation being performed.
            
        Returns:
            Combined list of taint labels.
        """
        combined_taints = []
        seen_ids = set()
        
        for inp in inputs:
            for taint in inp.taints:
                if taint.id not in seen_ids:
                    combined_taints.append(taint)
                    seen_ids.add(taint.id)
        
        return combined_taints
    
    def transform(
        self,
        input_data: TaintedData,
        output_content: str,
        operation: str = "transform",
    ) -> TaintedData:
        """
        Create tainted output from a transformation.
        
        Implements Rule 2 (Transformation):
        taint(transform(A)) = taint(A)
        
        Args:
            input_data: Input TaintedData.
            output_content: Transformed content.
            operation: Transformation operation name.
            
        Returns:
            TaintedData with propagated taints.
        """
        output_hash = hashlib.sha256(output_content.encode()).hexdigest()[:16]
        
        # Create edges from input taints to output
        output_taint = TaintLabel(
            source_type=TaintSourceType.MODEL_RESPONSE,
            source_id=f"transform_{operation}",
            sensitivity=input_data.max_sensitivity,
            label=f"transformed_{operation}",
            content_hash=output_hash,
        )
        
        # Create propagation edges
        for input_taint in input_data.taints:
            edge = TaintEdge(
                from_label_id=input_taint.id,
                to_label_id=output_taint.id,
                edge_type="transform",
                operation=operation,
            )
            if self.store:
                self.store.create_taint_edge(edge)
            else:
                self._pending_edges.append(edge)
        
        if self.store:
            self.store.create_taint_label(output_taint)
        else:
            self._pending_labels.append(output_taint)
        
        # Output inherits all input taints plus the new one
        return TaintedData(
            content=output_content,
            taints=input_data.taints + [output_taint],
            content_hash=output_hash,
        )
    
    def model_output(
        self,
        prompt: TaintedData,
        system_prompt: Optional[TaintedData],
        context: Optional[TaintedData],
        output_content: str,
        model_name: str,
    ) -> TaintedData:
        """
        Create tainted model output.
        
        Implements Rule 3 (Model Processing):
        taint(model_output) = taint(prompt) ∪ taint(system) ∪ taint(context)
        
        Args:
            prompt: User prompt (tainted).
            system_prompt: System prompt (tainted).
            context: Additional context (tainted).
            output_content: Model output.
            model_name: Name of the model.
            
        Returns:
            TaintedData with combined taints.
        """
        # Collect all inputs
        inputs = [prompt]
        if system_prompt:
            inputs.append(system_prompt)
        if context:
            inputs.append(context)
        
        # Propagate taints from all inputs
        combined_taints = self.propagate(*inputs, operation="model_inference")
        
        # Determine max sensitivity
        max_sens = TaintSensitivity.PUBLIC
        sens_order = [
            TaintSensitivity.PUBLIC,
            TaintSensitivity.INTERNAL,
            TaintSensitivity.CONFIDENTIAL,
            TaintSensitivity.RESTRICTED,
        ]
        for taint in combined_taints:
            if sens_order.index(taint.sensitivity) > sens_order.index(max_sens):
                max_sens = taint.sensitivity
        
        # Create model output taint
        output_hash = hashlib.sha256(output_content.encode()).hexdigest()[:16]
        model_taint = TaintLabel(
            source_type=TaintSourceType.MODEL_RESPONSE,
            source_id=model_name,
            sensitivity=max_sens,
            label=f"model:{model_name}",
            content_hash=output_hash,
        )
        
        if self.store:
            self.store.create_taint_label(model_taint)
        else:
            self._pending_labels.append(model_taint)
        
        # Create edges
        for input_taint in combined_taints:
            edge = TaintEdge(
                from_label_id=input_taint.id,
                to_label_id=model_taint.id,
                edge_type="propagate",
                operation="model_inference",
            )
            if self.store:
                self.store.create_taint_edge(edge)
            else:
                self._pending_edges.append(edge)
        
        return TaintedData(
            content=output_content,
            taints=combined_taints + [model_taint],
            content_hash=output_hash,
        )
    
    def tool_output(
        self,
        tool_input: TaintedData,
        output_content: str,
        tool_name: str,
    ) -> TaintedData:
        """
        Create tainted tool output.
        
        Implements Rule 4 (Tool Execution):
        taint(tool_output) = taint(tool_input) ∪ {tool:{tool_name}}
        
        Args:
            tool_input: Input to the tool (tainted).
            output_content: Tool output.
            tool_name: Name of the tool.
            
        Returns:
            TaintedData with propagated taints plus tool taint.
        """
        output_hash = hashlib.sha256(output_content.encode()).hexdigest()[:16]
        
        # Create tool taint
        tool_taint = TaintLabel(
            source_type=TaintSourceType.TOOL_OUTPUT,
            source_id=tool_name,
            sensitivity=tool_input.max_sensitivity,
            label=f"tool:{tool_name}",
            content_hash=output_hash,
        )
        
        if self.store:
            self.store.create_taint_label(tool_taint)
        else:
            self._pending_labels.append(tool_taint)
        
        # Create edges
        for input_taint in tool_input.taints:
            edge = TaintEdge(
                from_label_id=input_taint.id,
                to_label_id=tool_taint.id,
                edge_type="propagate",
                operation=f"tool_call:{tool_name}",
            )
            if self.store:
                self.store.create_taint_edge(edge)
            else:
                self._pending_edges.append(edge)
        
        return TaintedData(
            content=output_content,
            taints=tool_input.taints + [tool_taint],
            content_hash=output_hash,
        )
    
    def check_sink(
        self,
        data: TaintedData,
        sink_type: str,
    ) -> dict[str, Any]:
        """
        Check if tainted data should be allowed to reach a sink.
        
        Args:
            data: Tainted data to check.
            sink_type: Type of sink (response, tool_call, storage, export).
            
        Returns:
            Dict with check results and recommendations.
        """
        result = {
            "sink_type": sink_type,
            "allowed": True,
            "alerts": [],
            "sensitivity": data.max_sensitivity.value,
            "taints": [t.label for t in data.taints],
        }
        
        # Check based on sink type and sensitivity
        if sink_type == "response":
            if data.has_sensitivity(TaintSensitivity.RESTRICTED):
                result["alerts"].append({
                    "type": "restricted_data_in_response",
                    "message": "Restricted data detected in response",
                    "severity": "high",
                })
            elif data.has_sensitivity(TaintSensitivity.CONFIDENTIAL):
                result["alerts"].append({
                    "type": "confidential_data_in_response",
                    "message": "Confidential data detected in response",
                    "severity": "medium",
                })
        
        elif sink_type == "tool_call":
            if data.has_sensitivity(TaintSensitivity.RESTRICTED):
                result["allowed"] = False
                result["alerts"].append({
                    "type": "restricted_data_to_tool",
                    "message": "Cannot send restricted data to external tool",
                    "severity": "critical",
                })
        
        elif sink_type == "export":
            if data.has_sensitivity(TaintSensitivity.RESTRICTED):
                result["allowed"] = False
                result["alerts"].append({
                    "type": "restricted_data_export",
                    "message": "Export of restricted data requires approval",
                    "severity": "high",
                })
        
        return result
    
    def get_lineage(self, label_id: str) -> dict[str, Any]:
        """
        Get lineage graph for a taint label.
        
        Args:
            label_id: ID of the taint label.
            
        Returns:
            Lineage graph with nodes and edges.
        """
        if self.store:
            return self.store.get_taint_lineage(label_id)
        
        # Build from pending if no store
        nodes = []
        edges = []
        
        for label in self._pending_labels:
            if label.id == label_id:
                nodes.append({
                    "id": label.id,
                    "source_type": label.source_type.value,
                    "sensitivity": label.sensitivity.value,
                    "label": label.label,
                })
        
        for edge in self._pending_edges:
            if edge.from_label_id == label_id or edge.to_label_id == label_id:
                edges.append({
                    "id": edge.id,
                    "from": edge.from_label_id,
                    "to": edge.to_label_id,
                    "type": edge.edge_type,
                    "operation": edge.operation,
                })
        
        return {"nodes": nodes, "edges": edges}


# Global taint engine instance
_engine: Optional[TaintEngine] = None


def get_taint_engine(store=None) -> TaintEngine:
    """Get the global taint engine instance."""
    global _engine
    if _engine is None:
        _engine = TaintEngine(store)
    return _engine
