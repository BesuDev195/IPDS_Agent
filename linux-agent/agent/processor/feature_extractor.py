"""Feature Extractor and Adapter Module.

Extracts structured DDoS detection features from raw network traffic,
socket distributions, and UFW firewall logs. Provides configurable adapter
interfaces so features can be shaped to match the central backend ML model's schema.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from agent.collector.ufw_collector import UfwCollectionSummary
from agent.monitor.network_monitor import NetworkTelemetry


class DdosFeatures(BaseModel):
    """Normalized DDoS detection feature set computed over an observation window."""

    packet_rate: float = Field(0.0, description="Total incoming packets per second")
    byte_rate: float = Field(0.0, description="Total incoming bytes per second")
    connection_rate: float = Field(0.0, description="New/active connections per second")
    unique_source_ips: int = Field(0, description="Total distinct remote source IPs observed")
    tcp_syn_rate: float = Field(0.0, description="Incoming TCP SYN / SYN_RECV rate per second")
    failed_connection_count: int = Field(0, description="Number of dropped/blocked connection attempts")
    destination_port_distribution: Dict[int, int] = Field(
        default_factory=dict,
        description="Distribution of targeted destination ports",
    )
    traffic_window: float = Field(10.0, description="Observation time window in seconds")
    syn_ratio: float = Field(0.0, description="Ratio of SYN_RECV to established TCP connections")
    blocked_packet_count: int = Field(0, description="Packets dropped by firewall during window")
    blocked_ip_count: int = Field(0, description="Distinct IPs blocked by firewall during window")


class FeatureAdapter(ABC):
    """Abstract adapter interface to convert raw DdosFeatures into backend ML model schemas."""

    @abstractmethod
    def transform(self, features: DdosFeatures) -> Any:
        """Transforms DdosFeatures into the format expected by the model/backend."""
        raise NotImplementedError


class StandardDictAdapter(FeatureAdapter):
    """Default adapter: outputs a key-value dictionary with standard feature names."""

    def transform(self, features: DdosFeatures) -> Dict[str, Any]:
        return features.model_dump()


class OrderedVectorAdapter(FeatureAdapter):
    """Vector adapter: formats features as an ordered List[float] for vector-based models.

    Allows configuring exact feature ordering to match scikit-learn / PyTorch / ONNX pipelines.
    """

    DEFAULT_FEATURE_ORDER = [
        "packet_rate",
        "byte_rate",
        "connection_rate",
        "unique_source_ips",
        "tcp_syn_rate",
        "failed_connection_count",
        "syn_ratio",
        "blocked_packet_count",
        "traffic_window",
    ]

    def __init__(self, feature_order: Optional[List[str]] = None) -> None:
        self.feature_order = feature_order or self.DEFAULT_FEATURE_ORDER

    def transform(self, features: DdosFeatures) -> List[float]:
        feat_dict = features.model_dump()
        vector: List[float] = []
        for key in self.feature_order:
            val = feat_dict.get(key, 0.0)
            if isinstance(val, (int, float)):
                vector.append(float(val))
            elif isinstance(val, dict):
                # For dictionaries (e.g. port distribution), count unique targeted ports
                vector.append(float(len(val)))
            else:
                vector.append(0.0)
        return vector


class CustomMappingAdapter(FeatureAdapter):
    """Customizable schema adapter that supports field renaming and value transformations.

    Enables adaptation to external ML schemas without modifying the core agent code.
    """

    def __init__(
        self,
        field_mapping: Optional[Dict[str, str]] = None,
        value_transformers: Optional[Dict[str, Callable[[Any], Any]]] = None,
    ) -> None:
        # Map: internal_name -> backend_model_name
        self.field_mapping = field_mapping or {}
        # Transformers: backend_model_name -> func(val)
        self.value_transformers = value_transformers or {}

    def transform(self, features: DdosFeatures) -> Dict[str, Any]:
        raw_dict = features.model_dump()
        output: Dict[str, Any] = {}

        for internal_key, val in raw_dict.items():
            target_key = self.field_mapping.get(internal_key, internal_key)
            if target_key in self.value_transformers:
                output[target_key] = self.value_transformers[target_key](val)
            else:
                output[target_key] = val

        return output


class FeatureExtractor:
    """Calculates standardized DDoS features from network telemetry and firewall logs."""

    def __init__(self, adapter: Optional[FeatureAdapter] = None) -> None:
        self.adapter = adapter or StandardDictAdapter()

    def set_adapter(self, adapter: FeatureAdapter) -> None:
        """Updates the active schema adapter at runtime."""
        self.adapter = adapter

    def extract_raw_features(
        self,
        network_telemetry: Optional[NetworkTelemetry] = None,
        ufw_summary: Optional[UfwCollectionSummary] = None,
        window_seconds: float = 10.0,
    ) -> DdosFeatures:
        """Computes standardized DdosFeatures model from collectors."""
        window = max(0.1, window_seconds)

        packet_rate = 0.0
        byte_rate = 0.0
        syn_ratio = 0.0
        tcp_syn_rate = 0.0
        connection_rate = 0.0
        unique_ips_set: set[str] = set()
        port_dist: Dict[int, int] = {}
        failed_conns = 0

        # 1. Process network interface & socket connection telemetry
        if network_telemetry:
            traffic = network_telemetry.traffic
            conns = network_telemetry.connections

            packet_rate = traffic.incoming_packets_per_sec
            byte_rate = traffic.incoming_bytes_per_sec

            if traffic.measurement_window_seconds > 0:
                window = traffic.measurement_window_seconds

            syn_ratio = conns.syn_ratio
            tcp_syn_rate = round(conns.syn_recv_count / window, 2)
            connection_rate = round(conns.active_tcp_connections / window, 2)

            for ip in conns.top_remote_ips.keys():
                unique_ips_set.add(ip)

            for port, count in conns.top_local_ports.items():
                port_dist[port] = port_dist.get(port, 0) + count

            # Drop count from interfaces is a component of failed/dropped traffic
            failed_conns += traffic.total_drop_in

        # 2. Process UFW firewall log events
        blocked_packets = 0
        blocked_ips = 0

        if ufw_summary:
            blocked_packets = ufw_summary.total_blocked
            blocked_ips = ufw_summary.unique_blocked_ips
            failed_conns += blocked_packets

            for ip in ufw_summary.top_blocked_ips.keys():
                unique_ips_set.add(ip)

            for port, count in ufw_summary.top_targeted_ports.items():
                port_dist[port] = port_dist.get(port, 0) + count

        return DdosFeatures(
            packet_rate=packet_rate,
            byte_rate=byte_rate,
            connection_rate=connection_rate,
            unique_source_ips=len(unique_ips_set),
            tcp_syn_rate=tcp_syn_rate,
            failed_connection_count=failed_conns,
            destination_port_distribution=port_dist,
            traffic_window=window,
            syn_ratio=syn_ratio,
            blocked_packet_count=blocked_packets,
            blocked_ip_count=blocked_ips,
        )

    def extract(
        self,
        network_telemetry: Optional[NetworkTelemetry] = None,
        ufw_summary: Optional[UfwCollectionSummary] = None,
        window_seconds: float = 10.0,
    ) -> Any:
        """Extracts features and applies the configured schema adapter."""
        raw_features = self.extract_raw_features(
            network_telemetry=network_telemetry,
            ufw_summary=ufw_summary,
            window_seconds=window_seconds,
        )
        return self.adapter.transform(raw_features)

