import statistics
from typing import List, Dict, Any
from collections import defaultdict
import json

from ..models.analytics import RiskDistribution, AssetAnalysis, AnalyticsSummary
from ..models.batch import BatchResult

class AnalyticsService:
    """Service for generating analytics and insights from vulnerability data."""
    
    def __init__(self):
        self.score_ranges = {
            "0-10": (0, 10),
            "11-25": (11, 25),
            "26-50": (26, 50),
            "51-75": (51, 75),
            "76-100": (76, 100)
        }
    
    def analyze_batch_results(self, results: List[BatchResult]) -> AnalyticsSummary:
        """Analyze batch processing results and generate comprehensive analytics."""
        
        # Filter successful results
        successful_results = [r for r in results if r.status == "success"]
        
        if not successful_results:
            return self._empty_analytics_summary()
        
        # Generate risk distribution
        risk_distribution = self._calculate_risk_distribution(successful_results)
        
        # Generate asset analysis
        asset_analysis = self._calculate_asset_analysis(successful_results)
        
        # Get top critical vulnerabilities
        top_critical = self._get_top_critical_vulnerabilities(successful_results)
        
        # Generate trends based on actual data
        recent_trends = self._generate_trends_from_data(successful_results)
        
        # Processing stats
        processing_stats = {
            "total_processed": len(results),
            "successful_count": len(successful_results),
            "error_count": len(results) - len(successful_results),
            "success_rate": len(successful_results) / len(results) * 100 if results else 0
        }
        
        return AnalyticsSummary(
            risk_distribution=risk_distribution,
            asset_analysis=asset_analysis,
            top_critical_vulnerabilities=top_critical,
            recent_trends=recent_trends,
            processing_stats=processing_stats
        )
    
    def _calculate_risk_distribution(self, results: List[BatchResult]) -> RiskDistribution:
        """Calculate risk score distribution."""
        scores = [r.risk_score for r in results]
        
        # Count by priority
        priority_counts = defaultdict(int)
        for result in results:
            priority_counts[result.priority] += 1
        
        # Calculate score ranges
        score_ranges = defaultdict(int)
        for score in scores:
            for range_name, (min_score, max_score) in self.score_ranges.items():
                if min_score <= score <= max_score:
                    score_ranges[range_name] += 1
                    break
        
        return RiskDistribution(
            total_count=len(results),
            critical_count=priority_counts.get("CRITICAL", 0),
            high_count=priority_counts.get("HIGH", 0),
            medium_count=priority_counts.get("MEDIUM", 0),
            low_count=priority_counts.get("LOW", 0),
            unknown_count=priority_counts.get("UNKNOWN", 0),
            average_score=statistics.mean(scores) if scores else 0,
            median_score=statistics.median(scores) if scores else 0,
            score_ranges=dict(score_ranges)
        )
    
    def _calculate_asset_analysis(self, results: List[BatchResult]) -> List[AssetAnalysis]:
        """Analyze vulnerabilities by asset criticality."""
        # Group by asset criticality (we'll need to extract this from components)
        asset_groups = defaultdict(list)
        
        for result in results:
            # Extract asset criticality from components (approximate)
            criticality = self._extract_asset_criticality(result)
            asset_groups[criticality].append(result)
        
        asset_analysis = []
        for criticality, group_results in asset_groups.items():
            scores = [r.risk_score for r in group_results]
            
            # Count internet-facing (approximate based on exposure multiplier)
            internet_facing = sum(1 for r in group_results 
                                if r.components.get("exposure_multiplier", 1) > 1)
            
            asset_analysis.append(AssetAnalysis(
                criticality_level=criticality,
                count=len(group_results),
                average_risk_score=statistics.mean(scores) if scores else 0,
                internet_facing_count=internet_facing,
                internal_count=len(group_results) - internet_facing
            ))
        
        return sorted(asset_analysis, key=lambda x: x.criticality_level)
    
    def _extract_asset_criticality(self, result: BatchResult) -> int:
        """Extract asset criticality from risk calculation components."""
        # This is an approximation based on the criticality component
        criticality_component = result.components.get("criticality_component", 0)
        # Convert back to criticality level (1-10)
        if criticality_component > 2.5:
            return 9
        elif criticality_component > 2.0:
            return 8
        elif criticality_component > 1.5:
            return 7
        elif criticality_component > 1.0:
            return 6
        else:
            return 5
    
    def _get_top_critical_vulnerabilities(self, results: List[BatchResult], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top critical vulnerabilities by risk score."""
        critical_results = [r for r in results if r.priority == "CRITICAL"]
        sorted_critical = sorted(critical_results, key=lambda x: x.risk_score, reverse=True)
        
        return [
            {
                "cve_id": result.cve_id,
                "risk_score": result.risk_score,
                "timeline_days": result.timeline_days,
                "explanation": result.explanation[:100] + "..." if len(result.explanation) > 100 else result.explanation
            }
            for result in sorted_critical[:limit]
        ]
    
    def _generate_trends_from_data(self, results: List[BatchResult]) -> List[Dict[str, Any]]:
        """Generate trend data from actual results."""
        if not results:
            return []
        
        total_count = len(results)
        critical_count = sum(1 for r in results if r.priority == "CRITICAL")
        high_count = sum(1 for r in results if r.priority == "HIGH")
        medium_count = sum(1 for r in results if r.priority == "MEDIUM")
        low_count = sum(1 for r in results if r.priority == "LOW")
        avg_score = statistics.mean([r.risk_score for r in results]) if results else 0
        
        return [
            {
                "date": "Current Analysis",
                "total_vulnerabilities": total_count,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "average_risk_score": avg_score
            }
        ]
    
    def _empty_analytics_summary(self) -> AnalyticsSummary:
        """Return empty analytics summary when no data is available."""
        empty_distribution = RiskDistribution(
            total_count=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            unknown_count=0,
            average_score=0,
            median_score=0,
            score_ranges={}
        )
        
        return AnalyticsSummary(
            risk_distribution=empty_distribution,
            asset_analysis=[],
            top_critical_vulnerabilities=[],
            recent_trends=[],
            processing_stats={
                "total_processed": 0,
                "successful_count": 0,
                "error_count": 0,
                "success_rate": 0
            }
        ) 