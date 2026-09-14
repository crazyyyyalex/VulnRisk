"""
Performance Optimization Module for VulnRisk
Lightweight implementation focusing on core performance optimization
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
import statistics

logger = logging.getLogger(__name__)

class PerformanceMetric(Enum):
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    CACHE_HIT_RATE = "cache_hit_rate"

@dataclass
class PerformanceData:
    timestamp: datetime
    metric: PerformanceMetric
    value: float
    endpoint: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None

@dataclass
class CacheEntry:
    key: str
    value: Any
    timestamp: datetime
    ttl: int  # Time to live in seconds
    access_count: int = 0

class AdvancedCacheManager:
    """Advanced caching with multiple strategies"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache: Dict[str, CacheEntry] = {}
        self.access_times: Dict[str, datetime] = {}
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "size": 0
        }
        self.lock = threading.Lock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                
                # Check if expired
                if datetime.now() > entry.timestamp + timedelta(seconds=entry.ttl):
                    del self.cache[key]
                    del self.access_times[key]
                    self.stats["misses"] += 1
                    return None
                
                # Update access info
                entry.access_count += 1
                self.access_times[key] = datetime.now()
                self.stats["hits"] += 1
                return entry.value
            
            self.stats["misses"] += 1
            return None
    
    def set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """Set value in cache"""
        with self.lock:
            # Check if we need to evict
            if len(self.cache) >= self.max_size and key not in self.cache:
                self._evict_entries()
            
            entry = CacheEntry(
                key=key,
                value=value,
                timestamp=datetime.now(),
                ttl=ttl
            )
            
            self.cache[key] = entry
            self.access_times[key] = datetime.now()
            self.stats["size"] = len(self.cache)
            return True
    
    def _evict_entries(self):
        """Evict least recently used entries"""
        if not self.cache:
            return
        
        # Find least recently used entry
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        
        del self.cache[lru_key]
        del self.access_times[lru_key]
        self.stats["evictions"] += 1
        self.stats["size"] = len(self.cache)
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            self.stats["size"] = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.stats["hits"] + self.stats["misses"]
            hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                "size": self.stats["size"],
                "max_size": self.max_size,
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "evictions": self.stats["evictions"],
                "hit_rate": round(hit_rate, 2),
                "utilization": round((self.stats["size"] / self.max_size) * 100, 2)
            }
    
    def get_optimization_recommendations(self) -> List[str]:
        """Get cache optimization recommendations"""
        recommendations = []
        stats = self.get_stats()
        
        if stats["hit_rate"] < 70:
            recommendations.append("Consider increasing cache size or TTL to improve hit rate")
        
        if stats["utilization"] > 90:
            recommendations.append("Cache is nearly full, consider increasing max_size")
        
        if stats["evictions"] > 100:
            recommendations.append("High eviction rate, consider adjusting cache strategy")
        
        return recommendations

class DatabaseOptimizer:
    """Database performance optimization recommendations"""
    
    def __init__(self):
        self.query_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "count": 0,
            "total_time": 0.0,
            "avg_time": 0.0,
            "min_time": float('inf'),
            "max_time": 0.0,
            "last_executed": None
        })
        self.slow_queries: List[Dict[str, Any]] = []
        self.index_recommendations: List[str] = []
    
    def track_query(self, query: str, execution_time: float):
        """Track database query performance"""
        stats = self.query_stats[query]
        stats["count"] += 1
        stats["total_time"] += execution_time
        stats["avg_time"] = stats["total_time"] / stats["count"]
        stats["min_time"] = min(stats["min_time"], execution_time)
        stats["max_time"] = max(stats["max_time"], execution_time)
        stats["last_executed"] = datetime.now()
        
        # Track slow queries
        if execution_time > 1.0:  # Queries taking more than 1 second
            self.slow_queries.append({
                "query": query,
                "execution_time": execution_time,
                "timestamp": datetime.now()
            })
            
            # Keep only last 100 slow queries
            if len(self.slow_queries) > 100:
                self.slow_queries = self.slow_queries[-100:]
    
    def get_optimization_recommendations(self) -> Dict[str, Any]:
        """Get database optimization recommendations"""
        recommendations = {
            "slow_queries": [],
            "index_recommendations": [],
            "general_recommendations": []
        }
        
        # Analyze slow queries
        for query_data in self.slow_queries[-10:]:  # Last 10 slow queries
            recommendations["slow_queries"].append({
                "query": query_data["query"][:100] + "..." if len(query_data["query"]) > 100 else query_data["query"],
                "execution_time": query_data["execution_time"],
                "timestamp": query_data["timestamp"].isoformat()
            })
        
        # Generate index recommendations based on query patterns
        for query, stats in self.query_stats.items():
            if stats["avg_time"] > 0.5:  # Queries averaging more than 500ms
                if "WHERE" in query.upper():
                    recommendations["index_recommendations"].append(
                        f"Consider adding indexes for WHERE clauses in query: {query[:50]}..."
                    )
                if "ORDER BY" in query.upper():
                    recommendations["index_recommendations"].append(
                        f"Consider adding indexes for ORDER BY clauses in query: {query[:50]}..."
                    )
        
        # General recommendations
        if len(self.slow_queries) > 50:
            recommendations["general_recommendations"].append(
                "High number of slow queries detected. Consider query optimization or database tuning."
            )
        
        total_queries = sum(stats["count"] for stats in self.query_stats.values())
        if total_queries > 10000:
            recommendations["general_recommendations"].append(
                "High query volume detected. Consider implementing query result caching."
            )
        
        return recommendations
    
    def get_query_stats(self) -> Dict[str, Any]:
        """Get database query statistics"""
        total_queries = sum(stats["count"] for stats in self.query_stats.values())
        total_time = sum(stats["total_time"] for stats in self.query_stats.values())
        
        return {
            "total_queries": total_queries,
            "total_time": total_time,
            "avg_query_time": total_time / total_queries if total_queries > 0 else 0,
            "unique_queries": len(self.query_stats),
            "slow_queries_count": len(self.slow_queries),
            "top_queries": sorted(
                self.query_stats.items(),
                key=lambda x: x[1]["count"],
                reverse=True
            )[:10]
        }

class PerformanceMonitor:
    """Real-time performance monitoring"""
    
    def __init__(self):
        self.metrics: deque = deque(maxlen=10000)  # Keep last 10k metrics
        self.alerts: List[Dict[str, Any]] = []
        self.thresholds = {
            PerformanceMetric.RESPONSE_TIME: 2.0,  # 2 seconds
            PerformanceMetric.ERROR_RATE: 5.0,     # 5%
            PerformanceMetric.CPU_USAGE: 80.0,     # 80%
            PerformanceMetric.MEMORY_USAGE: 85.0,  # 85%
        }
        self.lock = threading.Lock()
    
    def record_metric(self, metric: PerformanceMetric, value: float, 
                     endpoint: Optional[str] = None, user_id: Optional[str] = None,
                     request_id: Optional[str] = None):
        """Record a performance metric"""
        with self.lock:
            data = PerformanceData(
                timestamp=datetime.now(),
                metric=metric,
                value=value,
                endpoint=endpoint,
                user_id=user_id,
                request_id=request_id
            )
            
            self.metrics.append(data)
            
            # Check for alerts
            if metric in self.thresholds and value > self.thresholds[metric]:
                self._create_alert(metric, value, endpoint)
    
    def _create_alert(self, metric: PerformanceMetric, value: float, endpoint: Optional[str]):
        """Create a performance alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "metric": metric.value,
            "value": value,
            "threshold": self.thresholds[metric],
            "endpoint": endpoint,
            "severity": "high" if value > self.thresholds[metric] * 1.5 else "medium",
            "message": f"{metric.value} exceeded threshold: {value} > {self.thresholds[metric]}"
        }
        
        self.alerts.append(alert)
        logger.warning(f"Performance Alert: {alert['message']}")
        
        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
    
    def get_performance_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get performance summary for the specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.lock:
            recent_metrics = [
                m for m in self.metrics 
                if m.timestamp >= cutoff_time
            ]
        
        if not recent_metrics:
            return {"message": "No metrics available for the specified time period"}
        
        # Group by metric type
        metrics_by_type = defaultdict(list)
        for metric in recent_metrics:
            metrics_by_type[metric.metric].append(metric.value)
        
        summary = {
            "time_period_hours": hours,
            "total_metrics": len(recent_metrics),
            "metrics_by_type": {},
            "alerts_count": len([a for a in self.alerts if datetime.fromisoformat(a["timestamp"]) >= cutoff_time])
        }
        
        for metric_type, values in metrics_by_type.items():
            summary["metrics_by_type"][metric_type.value] = {
                "count": len(values),
                "average": round(statistics.mean(values), 3),
                "min": round(min(values), 3),
                "max": round(max(values), 3),
                "median": round(statistics.median(values), 3)
            }
        
        return summary
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent performance alerts"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.lock:
            recent_alerts = [
                alert for alert in self.alerts
                if datetime.fromisoformat(alert["timestamp"]) >= cutoff_time
            ]
        
        return recent_alerts
    
    def set_threshold(self, metric: PerformanceMetric, threshold: float):
        """Set performance threshold"""
        self.thresholds[metric] = threshold
    
    def get_thresholds(self) -> Dict[str, float]:
        """Get current performance thresholds"""
        return {metric.value: threshold for metric, threshold in self.thresholds.items()}

# Global instances
cache_manager = AdvancedCacheManager()
db_optimizer = DatabaseOptimizer()
performance_monitor = PerformanceMonitor() 