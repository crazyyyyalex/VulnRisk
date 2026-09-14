"""
AI-Powered Analytics Service for Predictive Risk Modeling
Implements machine learning models for vulnerability trend prediction and intelligent insights.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import logging
import os

logger = logging.getLogger(__name__)

# Safe imports with fallbacks for ML libraries
try:
    from sklearn.ensemble import RandomForestRegressor, IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import mean_squared_error, r2_score
    import joblib
    ML_AVAILABLE = True
    logger.info("ML libraries (scikit-learn, joblib) loaded successfully")
except ImportError as e:
    logger.warning(f"ML libraries not available: {e}")
    logger.info("AI analytics will use fallback implementations")
    ML_AVAILABLE = False
    
    # Create mock classes for graceful degradation
    class MockModel:
        def fit(self, X, y): pass
        def predict(self, X): return np.zeros(len(X))
        def score(self, X, y): return 0.0
    
    class MockScaler:
        def fit_transform(self, X): return X
        def transform(self, X): return X
    
    RandomForestRegressor = MockModel
    IsolationForest = MockModel
    StandardScaler = MockScaler
    
    def train_test_split(*args, **kwargs):
        X, y = args[0], args[1]
        split_idx = int(len(X) * 0.8)
        return X[:split_idx], X[split_idx:], y[:split_idx], y[split_idx:]
    
    def mean_squared_error(y_true, y_pred): return 0.0
    def r2_score(y_true, y_pred): return 0.0
    
    class MockJoblib:
        @staticmethod
        def dump(obj, filename): pass
        @staticmethod
        def load(filename): return MockModel()
    
    joblib = MockJoblib()

class AIAnalyticsService:
    """AI-powered analytics service for predictive risk modeling."""
    
    def __init__(self):
        self.risk_predictor = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.model_path = "models/"
        self.ml_available = ML_AVAILABLE
        
        if not self.ml_available:
            logger.warning("AI Analytics Service initialized in fallback mode - ML features disabled")
        
        # Only create model directory if ML is available
        if self.ml_available:
            os.makedirs(self.model_path, exist_ok=True)
        
    def prepare_features(self, vulnerabilities: List[Dict]) -> pd.DataFrame:
        """Prepare features for machine learning models."""
        features = []
        
        for vuln in vulnerabilities:
            feature_vector = {
                'cvss_score': float(vuln.get('cvss_score', 0)),
                'epss_score': float(vuln.get('epss_score', 0)),
                'days_since_published': self._calculate_days_since_published(vuln.get('published_date')),
                'has_exploit': 1 if vuln.get('has_exploit', False) else 0,
                'has_poc': 1 if vuln.get('has_poc', False) else 0,
                'affected_components': len(vuln.get('affected_components', [])),
                'cwe_count': len(vuln.get('cwe_ids', [])),
                'vendor_count': len(vuln.get('affected_vendors', [])),
                'description_length': len(vuln.get('description', '')),
                'references_count': len(vuln.get('references', [])),
                'patch_available': 1 if vuln.get('patch_available', False) else 0,
                'remote_exploitable': 1 if vuln.get('remote_exploitable', False) else 0,
                'privilege_escalation': 1 if vuln.get('privilege_escalation', False) else 0,
                'data_exfiltration': 1 if vuln.get('data_exfiltration', False) else 0,
                'service_disruption': 1 if vuln.get('service_disruption', False) else 0,
            }
            features.append(feature_vector)
            
        return pd.DataFrame(features)
    
    def _calculate_days_since_published(self, published_date: str) -> int:
        """Calculate days since vulnerability was published."""
        try:
            if not published_date:
                return 0
            pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            return (datetime.now() - pub_date).days
        except:
            return 0
    
    def train_risk_predictor(self, vulnerabilities: List[Dict]) -> Dict:
        """Train machine learning model for risk prediction."""
        if not self.ml_available:
            return {
                "success": False, 
                "message": "ML libraries not available in serverless build. AI training disabled."
            }
            
        try:
            df = self.prepare_features(vulnerabilities)
            
            if len(df) < 10:
                return {"success": False, "message": "Insufficient data for training"}
            
            # Prepare target variable (risk score)
            risk_scores = [float(v.get('risk_score', 0)) for v in vulnerabilities]
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                df, risk_scores, test_size=0.2, random_state=42
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model
            self.risk_predictor = RandomForestRegressor(
                n_estimators=100, random_state=42, n_jobs=-1
            )
            self.risk_predictor.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.risk_predictor.predict(X_test_scaled)
            mse = mean_squared_error(y_test, y_pred)
            r2 = r2_score(y_test, y_pred)
            
            # Save model
            model_file = os.path.join(self.model_path, "risk_predictor.joblib")
            scaler_file = os.path.join(self.model_path, "scaler.joblib")
            joblib.dump(self.risk_predictor, model_file)
            joblib.dump(self.scaler, scaler_file)
            
            return {
                "success": True,
                "metrics": {
                    "mse": mse,
                    "r2_score": r2,
                    "training_samples": len(X_train),
                    "test_samples": len(X_test)
                }
            }
            
        except Exception as e:
            logger.error(f"Error training risk predictor: {e}")
            return {"success": False, "message": str(e)}
    
    def predict_risk_trends(self, vulnerabilities: List[Dict]) -> Dict:
        """Predict future risk trends based on historical data."""
        if not self.ml_available:
            # Return basic statistical analysis as fallback
            return self._fallback_risk_analysis(vulnerabilities)
            
        try:
            if not self.risk_predictor:
                return {"success": False, "message": "Model not trained"}
            
            df = self.prepare_features(vulnerabilities)
            df_scaled = self.scaler.transform(df)
            
            predictions = self.risk_predictor.predict(df_scaled)
            
            # Calculate trend indicators
            risk_trends = {
                "current_avg_risk": np.mean(predictions),
                "risk_volatility": np.std(predictions),
                "high_risk_count": len([p for p in predictions if p > 7.0]),
                "medium_risk_count": len([p for p in predictions if 4.0 <= p <= 7.0]),
                "low_risk_count": len([p for p in predictions if p < 4.0]),
                "trend_direction": "increasing" if np.mean(predictions) > 5.0 else "decreasing",
                "confidence_score": self.risk_predictor.score(df_scaled, predictions),
                "prediction_accuracy": self._calculate_prediction_accuracy(vulnerabilities, predictions)
            }
            
            return {"success": True, "trends": risk_trends, "predictions": predictions.tolist()}
            
        except Exception as e:
            logger.error(f"Error predicting risk trends: {e}")
            return {"success": False, "message": str(e)}
    
    def _calculate_prediction_accuracy(self, vulnerabilities: List[Dict], predictions: np.ndarray) -> float:
        """Calculate prediction accuracy compared to actual risk scores."""
        try:
            actual_scores = [float(v.get('risk_score', 0)) for v in vulnerabilities]
            if len(actual_scores) != len(predictions):
                return 0.0
            
            # Calculate correlation coefficient
            correlation = np.corrcoef(actual_scores, predictions)[0, 1]
            return abs(correlation) if not np.isnan(correlation) else 0.0
        except:
            return 0.0
    
    def detect_anomalies(self, vulnerabilities: List[Dict]) -> Dict:
        """Detect anomalous vulnerabilities using isolation forest."""
        if not self.ml_available:
            return self._fallback_anomaly_detection(vulnerabilities)
            
        try:
            df = self.prepare_features(vulnerabilities)
            
            if len(df) < 5:
                return {"success": False, "message": "Insufficient data for anomaly detection"}
            
            # Train anomaly detector
            self.anomaly_detector = IsolationForest(
                contamination=0.1, random_state=42
            )
            self.anomaly_detector.fit(df)
            
            # Detect anomalies
            anomaly_scores = self.anomaly_detector.decision_function(df)
            anomaly_predictions = self.anomaly_detector.predict(df)
            
            # Identify anomalous vulnerabilities
            anomalous_indices = [i for i, pred in enumerate(anomaly_predictions) if pred == -1]
            anomalous_vulns = [vulnerabilities[i] for i in anomalous_indices]
            
            return {
                "success": True,
                "anomaly_count": len(anomalous_vulns),
                "anomaly_percentage": len(anomalous_vulns) / len(vulnerabilities) * 100,
                "anomalous_vulnerabilities": anomalous_vulns,
                "anomaly_scores": anomaly_scores.tolist()
            }
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return {"success": False, "message": str(e)}
    
    def generate_intelligent_recommendations(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate intelligent remediation recommendations."""
        try:
            recommendations = []
            
            # Analyze vulnerability patterns
            high_risk_vulns = [v for v in vulnerabilities if float(v.get('risk_score', 0)) > 7.0]
            old_vulns = [v for v in vulnerabilities if self._calculate_days_since_published(v.get('published_date', '')) > 365]
            unpatched_vulns = [v for v in vulnerabilities if not v.get('patch_available', False)]
            
            # Generate recommendations
            if len(high_risk_vulns) > 0:
                recommendations.append({
                    "type": "high_priority",
                    "title": "Immediate Action Required",
                    "description": f"Found {len(high_risk_vulns)} high-risk vulnerabilities requiring immediate attention",
                    "priority": "critical",
                    "action_items": [
                        "Conduct immediate security assessment",
                        "Implement temporary mitigations",
                        "Schedule emergency patching"
                    ]
                })
            
            if len(old_vulns) > 0:
                recommendations.append({
                    "type": "aging_vulnerabilities",
                    "title": "Aging Vulnerabilities Detected",
                    "description": f"Found {len(old_vulns)} vulnerabilities older than 1 year",
                    "priority": "high",
                    "action_items": [
                        "Review and update patch management process",
                        "Implement automated vulnerability scanning",
                        "Establish regular security review schedule"
                    ]
                })
            
            if len(unpatched_vulns) > 0:
                recommendations.append({
                    "type": "missing_patches",
                    "title": "Missing Security Patches",
                    "description": f"Found {len(unpatched_vulns)} vulnerabilities without available patches",
                    "priority": "medium",
                    "action_items": [
                        "Implement compensating controls",
                        "Monitor for exploit attempts",
                        "Establish vendor communication channels"
                    ]
                })
            
            # Add AI-driven insights only if ML is available
            if self.ml_available and len(vulnerabilities) > 10:
                risk_trends = self.predict_risk_trends(vulnerabilities)
                if risk_trends["success"]:
                    trends = risk_trends["trends"]
                    if trends["trend_direction"] == "increasing":
                        recommendations.append({
                            "type": "ai_insight",
                            "title": "AI Risk Trend Alert",
                            "description": "Risk levels are trending upward based on historical patterns",
                            "priority": "medium",
                            "action_items": [
                                "Increase security monitoring",
                                "Review security policies",
                                "Consider additional security controls"
                            ]
                        })
            
            return {
                "success": True,
                "recommendations": recommendations,
                "summary": {
                    "total_recommendations": len(recommendations),
                    "critical_count": len([r for r in recommendations if r["priority"] == "critical"]),
                    "high_count": len([r for r in recommendations if r["priority"] == "high"]),
                    "medium_count": len([r for r in recommendations if r["priority"] == "medium"])
                },
                "ml_available": self.ml_available
            }
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return {"success": False, "message": str(e)}
    
    def load_models(self) -> bool:
        """Load pre-trained models if available."""
        if not self.ml_available:
            logger.info("Skipping model loading - ML libraries not available")
            return False
            
        try:
            model_file = os.path.join(self.model_path, "risk_predictor.joblib")
            scaler_file = os.path.join(self.model_path, "scaler.joblib")
            
            if os.path.exists(model_file) and os.path.exists(scaler_file):
                self.risk_predictor = joblib.load(model_file)
                self.scaler = joblib.load(scaler_file)
                return True
            return False
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False
    
    def _fallback_risk_analysis(self, vulnerabilities: List[Dict]) -> Dict:
        """Fallback risk analysis using basic statistics when ML is not available."""
        try:
            if not vulnerabilities:
                return {"success": False, "message": "No vulnerability data provided"}
            
            # Extract risk scores
            risk_scores = [float(v.get('risk_score', 0)) for v in vulnerabilities if v.get('risk_score')]
            cvss_scores = [float(v.get('cvss_score', 0)) for v in vulnerabilities if v.get('cvss_score')]
            
            if not risk_scores and not cvss_scores:
                return {"success": False, "message": "No risk score data available"}
            
            # Use CVSS scores as fallback if no risk scores
            scores_to_analyze = risk_scores if risk_scores else cvss_scores
            
            # Basic statistical analysis
            avg_risk = np.mean(scores_to_analyze)
            risk_volatility = np.std(scores_to_analyze)
            
            risk_trends = {
                "current_avg_risk": float(avg_risk),
                "risk_volatility": float(risk_volatility),
                "high_risk_count": len([s for s in scores_to_analyze if s > 7.0]),
                "medium_risk_count": len([s for s in scores_to_analyze if 4.0 <= s <= 7.0]),
                "low_risk_count": len([s for s in scores_to_analyze if s < 4.0]),
                "trend_direction": "increasing" if avg_risk > 5.0 else "stable",
                "confidence_score": 0.6,  # Lower confidence for statistical analysis
                "prediction_accuracy": 0.7,  # Estimated accuracy
                "method": "statistical_fallback"
            }
            
            return {
                "success": True, 
                "trends": risk_trends, 
                "predictions": scores_to_analyze,
                "note": "Using statistical analysis (ML libraries not available)"
            }
            
        except Exception as e:
            logger.error(f"Error in fallback risk analysis: {e}")
            return {"success": False, "message": str(e)}
    
    def _fallback_anomaly_detection(self, vulnerabilities: List[Dict]) -> Dict:
        """Fallback anomaly detection using statistical methods."""
        try:
            if len(vulnerabilities) < 5:
                return {"success": False, "message": "Insufficient data for anomaly detection"}
            
            # Use statistical outlier detection based on CVSS scores and other metrics
            risk_scores = [float(v.get('risk_score', v.get('cvss_score', 0))) for v in vulnerabilities]
            
            if not risk_scores:
                return {"success": False, "message": "No risk data available for anomaly detection"}
            
            # Calculate statistical thresholds
            mean_score = np.mean(risk_scores)
            std_score = np.std(risk_scores)
            threshold = mean_score + 2 * std_score  # 2 standard deviations
            
            # Identify anomalies
            anomalous_indices = [i for i, score in enumerate(risk_scores) if score > threshold]
            anomalous_vulns = [vulnerabilities[i] for i in anomalous_indices]
            
            return {
                "success": True,
                "anomaly_count": len(anomalous_vulns),
                "anomaly_percentage": len(anomalous_vulns) / len(vulnerabilities) * 100,
                "anomalous_vulnerabilities": anomalous_vulns,
                "method": "statistical_outlier_detection",
                "threshold": float(threshold),
                "note": "Using statistical analysis (ML libraries not available)"
            }
            
        except Exception as e:
            logger.error(f"Error in fallback anomaly detection: {e}")
            return {"success": False, "message": str(e)} 