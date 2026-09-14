"""
Auto-scaling and Load Balancing Module for VulnRisk
Lightweight implementation focusing on core scaling features
"""

import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from enum import Enum
import threading
import random

logger = logging.getLogger(__name__)

class ScalingAction(Enum):
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    NO_ACTION = "no_action"

class LoadBalancingStrategy(Enum):
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED = "weighted"

@dataclass
class BackendInstance:
    id: str
    host: str
    port: int
    weight: int = 1
    health_status: str = "healthy"
    last_health_check: datetime = None
    connection_count: int = 0
    response_time: float = 0.0
    is_active: bool = True

@dataclass
class ScalingEvent:
    timestamp: datetime
    action: ScalingAction
    reason: str
    current_instances: int
    target_instances: int
    metrics: Dict[str, float]

class AutoScalingManager:
    """Auto-scaling manager for dynamic resource management"""
    
    def __init__(self):
        self.current_instances = 1
        self.min_instances = 1
        self.max_instances = 10
        self.scaling_cooldown = 300  # 5 minutes
        self.last_scale_time = None
        
        # Scaling thresholds
        self.thresholds = {
            "cpu_usage": 80.0,      # Scale up if CPU > 80%
            "memory_usage": 85.0,   # Scale up if memory > 85%
            "response_time": 2.0,   # Scale up if response time > 2s
            "error_rate": 5.0,      # Scale up if error rate > 5%
            "load": 100.0,          # Scale up if load > 100
        }
        
        # Scaling events history
        self.scaling_events: deque = deque(maxlen=100)
        self.metrics_history: deque = deque(maxlen=1000)
        self.lock = threading.Lock()
    
    def evaluate_scaling(self, current_metrics: Dict[str, float]) -> ScalingAction:
        """Evaluate if scaling is needed based on current metrics"""
        with self.lock:
            # Record metrics
            self.metrics_history.append({
                "timestamp": datetime.now(),
                "metrics": current_metrics
            })
            
            # Check cooldown period
            if self.last_scale_time and (datetime.now() - self.last_scale_time).seconds < self.scaling_cooldown:
                return ScalingAction.NO_ACTION
            
            # Determine scaling action
            action = self._determine_scaling_action(current_metrics)
            
            if action != ScalingAction.NO_ACTION:
                self._record_scaling_event(action, current_metrics)
                self.last_scale_time = datetime.now()
            
            return action
    
    def _determine_scaling_action(self, metrics: Dict[str, float]) -> ScalingAction:
        """Determine scaling action based on metrics"""
        scale_up_reasons = []
        scale_down_reasons = []
        
        # Check scale up conditions
        if metrics.get("cpu_usage", 0) > self.thresholds["cpu_usage"]:
            scale_up_reasons.append(f"CPU usage {metrics['cpu_usage']}% > {self.thresholds['cpu_usage']}%")
        
        if metrics.get("memory_usage", 0) > self.thresholds["memory_usage"]:
            scale_up_reasons.append(f"Memory usage {metrics['memory_usage']}% > {self.thresholds['memory_usage']}%")
        
        if metrics.get("response_time", 0) > self.thresholds["response_time"]:
            scale_up_reasons.append(f"Response time {metrics['response_time']}s > {self.thresholds['response_time']}s")
        
        if metrics.get("error_rate", 0) > self.thresholds["error_rate"]:
            scale_up_reasons.append(f"Error rate {metrics['error_rate']}% > {self.thresholds['error_rate']}%")
        
        if metrics.get("load", 0) > self.thresholds["load"]:
            scale_up_reasons.append(f"Load {metrics['load']} > {self.thresholds['load']}")
        
        # Check scale down conditions (only if we have more than min instances)
        if self.current_instances > self.min_instances:
            if (metrics.get("cpu_usage", 0) < 30 and 
                metrics.get("memory_usage", 0) < 40 and
                metrics.get("response_time", 0) < 0.5 and
                metrics.get("error_rate", 0) < 1.0):
                scale_down_reasons.append("Low resource utilization")
        
        # Determine action
        if scale_up_reasons and self.current_instances < self.max_instances:
            return ScalingAction.SCALE_UP
        elif scale_down_reasons and self.current_instances > self.min_instances:
            return ScalingAction.SCALE_DOWN
        
        return ScalingAction.NO_ACTION
    
    def _record_scaling_event(self, action: ScalingAction, metrics: Dict[str, float]):
        """Record a scaling event"""
        event = ScalingEvent(
            timestamp=datetime.now(),
            action=action,
            reason=self._get_scaling_reason(action, metrics),
            current_instances=self.current_instances,
            target_instances=self._calculate_target_instances(action),
            metrics=metrics
        )
        
        self.scaling_events.append(event)
        logger.info(f"Scaling event: {action.value} - {event.reason}")
    
    def _get_scaling_reason(self, action: ScalingAction, metrics: Dict[str, float]) -> str:
        """Get human-readable scaling reason"""
        if action == ScalingAction.SCALE_UP:
            reasons = []
            if metrics.get("cpu_usage", 0) > self.thresholds["cpu_usage"]:
                reasons.append("high CPU usage")
            if metrics.get("memory_usage", 0) > self.thresholds["memory_usage"]:
                reasons.append("high memory usage")
            if metrics.get("response_time", 0) > self.thresholds["response_time"]:
                reasons.append("high response time")
            if metrics.get("error_rate", 0) > self.thresholds["error_rate"]:
                reasons.append("high error rate")
            return f"Scale up due to: {', '.join(reasons)}"
        elif action == ScalingAction.SCALE_DOWN:
            return "Scale down due to low resource utilization"
        else:
            return "No scaling action needed"
    
    def _calculate_target_instances(self, action: ScalingAction) -> int:
        """Calculate target number of instances"""
        if action == ScalingAction.SCALE_UP:
            return min(self.current_instances + 1, self.max_instances)
        elif action == ScalingAction.SCALE_DOWN:
            return max(self.current_instances - 1, self.min_instances)
        else:
            return self.current_instances
    
    def execute_scaling(self, action: ScalingAction) -> bool:
        """Execute scaling action"""
        with self.lock:
            if action == ScalingAction.SCALE_UP and self.current_instances < self.max_instances:
                self.current_instances += 1
                logger.info(f"Scaled up to {self.current_instances} instances")
                return True
            elif action == ScalingAction.SCALE_DOWN and self.current_instances > self.min_instances:
                self.current_instances -= 1
                logger.info(f"Scaled down to {self.current_instances} instances")
                return True
        
        return False
    
    def set_threshold(self, metric: str, threshold: float):
        """Set scaling threshold for a metric"""
        if metric in self.thresholds:
            self.thresholds[metric] = threshold
            logger.info(f"Updated {metric} threshold to {threshold}")
    
    def get_scaling_status(self) -> Dict[str, Any]:
        """Get current scaling status"""
        with self.lock:
            return {
                "current_instances": self.current_instances,
                "min_instances": self.min_instances,
                "max_instances": self.max_instances,
                "thresholds": self.thresholds.copy(),
                "last_scale_time": self.last_scale_time.isoformat() if self.last_scale_time else None,
                "scaling_cooldown": self.scaling_cooldown,
                "recent_events": [
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "action": event.action.value,
                        "reason": event.reason,
                        "instances": f"{event.current_instances} -> {event.target_instances}"
                    }
                    for event in list(self.scaling_events)[-5:]  # Last 5 events
                ]
            }
    
    def get_scaling_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get scaling history for the specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.lock:
            recent_events = [
                asdict(event) for event in self.scaling_events
                if event.timestamp >= cutoff_time
            ]
        
        return recent_events

class LoadBalancer:
    """Load balancer for distributing requests across backend instances"""
    
    def __init__(self, strategy: LoadBalancingStrategy = LoadBalancingStrategy.ROUND_ROBIN):
        self.strategy = strategy
        self.instances: List[BackendInstance] = []
        self.current_index = 0  # For round-robin
        self.lock = threading.Lock()
        
        # Health check configuration
        self.health_check_interval = 30  # seconds
        self.health_check_timeout = 5    # seconds
        self.unhealthy_threshold = 3     # consecutive failures
    
    def add_instance(self, instance: BackendInstance):
        """Add a backend instance"""
        with self.lock:
            self.instances.append(instance)
            logger.info(f"Added backend instance: {instance.host}:{instance.port}")
    
    def remove_instance(self, instance_id: str):
        """Remove a backend instance"""
        with self.lock:
            self.instances = [inst for inst in self.instances if inst.id != instance_id]
            logger.info(f"Removed backend instance: {instance_id}")
    
    def get_next_instance(self) -> Optional[BackendInstance]:
        """Get next instance based on load balancing strategy"""
        with self.lock:
            healthy_instances = [inst for inst in self.instances if inst.is_active and inst.health_status == "healthy"]
            
            if not healthy_instances:
                logger.warning("No healthy backend instances available")
                return None
            
            if self.strategy == LoadBalancingStrategy.ROUND_ROBIN:
                return self._round_robin_select(healthy_instances)
            elif self.strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
                return self._least_connections_select(healthy_instances)
            elif self.strategy == LoadBalancingStrategy.WEIGHTED:
                return self._weighted_select(healthy_instances)
            else:
                return healthy_instances[0]  # Default to first healthy instance
    
    def _round_robin_select(self, instances: List[BackendInstance]) -> BackendInstance:
        """Round-robin selection"""
        instance = instances[self.current_index % len(instances)]
        self.current_index += 1
        return instance
    
    def _least_connections_select(self, instances: List[BackendInstance]) -> BackendInstance:
        """Least connections selection"""
        return min(instances, key=lambda inst: inst.connection_count)
    
    def _weighted_select(self, instances: List[BackendInstance]) -> BackendInstance:
        """Weighted selection based on instance weights"""
        total_weight = sum(inst.weight for inst in instances)
        if total_weight == 0:
            return instances[0]
        
        # Simple weighted random selection
        rand = random.uniform(0, total_weight)
        current_weight = 0
        
        for instance in instances:
            current_weight += instance.weight
            if rand <= current_weight:
                return instance
        
        return instances[-1]  # Fallback
    
    def update_instance_health(self, instance_id: str, health_status: str, response_time: float = 0.0):
        """Update instance health status"""
        with self.lock:
            for instance in self.instances:
                if instance.id == instance_id:
                    instance.health_status = health_status
                    instance.last_health_check = datetime.now()
                    instance.response_time = response_time
                    break
    
    def increment_connection_count(self, instance_id: str):
        """Increment connection count for an instance"""
        with self.lock:
            for instance in self.instances:
                if instance.id == instance_id:
                    instance.connection_count += 1
                    break
    
    def decrement_connection_count(self, instance_id: str):
        """Decrement connection count for an instance"""
        with self.lock:
            for instance in self.instances:
                if instance.id == instance_id:
                    instance.connection_count = max(0, instance.connection_count - 1)
                    break
    
    def get_load_balancer_status(self) -> Dict[str, Any]:
        """Get load balancer status"""
        with self.lock:
            total_instances = len(self.instances)
            healthy_instances = len([inst for inst in self.instances if inst.health_status == "healthy"])
            total_connections = sum(inst.connection_count for inst in self.instances)
            
            return {
                "strategy": self.strategy.value,
                "total_instances": total_instances,
                "healthy_instances": healthy_instances,
                "unhealthy_instances": total_instances - healthy_instances,
                "total_connections": total_connections,
                "instances": [
                    {
                        "id": inst.id,
                        "host": inst.host,
                        "port": inst.port,
                        "health_status": inst.health_status,
                        "connection_count": inst.connection_count,
                        "response_time": inst.response_time,
                        "is_active": inst.is_active,
                        "last_health_check": inst.last_health_check.isoformat() if inst.last_health_check else None
                    }
                    for inst in self.instances
                ]
            }
    
    def set_strategy(self, strategy: LoadBalancingStrategy):
        """Set load balancing strategy"""
        self.strategy = strategy
        logger.info(f"Load balancing strategy changed to: {strategy.value}")
    
    def health_check_all_instances(self) -> Dict[str, bool]:
        """Perform health check on all instances"""
        health_results = {}
        
        for instance in self.instances:
            try:
                # Simulate health check (in real implementation, this would make HTTP requests)
                is_healthy = self._perform_health_check(instance)
                health_results[instance.id] = is_healthy
                
                # Update instance health status
                self.update_instance_health(
                    instance.id,
                    "healthy" if is_healthy else "unhealthy"
                )
                
            except Exception as e:
                logger.error(f"Health check failed for instance {instance.id}: {e}")
                health_results[instance.id] = False
                self.update_instance_health(instance.id, "unhealthy")
        
        return health_results
    
    def _perform_health_check(self, instance: BackendInstance) -> bool:
        """Perform health check on a single instance"""
        # This is a simplified health check
        # In a real implementation, this would make an HTTP request to the instance
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.health_check_timeout)
            result = sock.connect_ex((instance.host, instance.port))
            sock.close()
            return result == 0
        except Exception:
            return False

# Global instances
auto_scaling_manager = AutoScalingManager()
load_balancer = LoadBalancer() 