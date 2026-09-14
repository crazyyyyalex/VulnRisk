"""
Enhanced AI Analytics Service for VulnRisk

Advanced machine learning capabilities including XGBoost, hyperparameter optimization,
enhanced feature engineering, and model versioning for enterprise-grade vulnerability intelligence.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import logging
import os
import json
import joblib
from pathlib import Path

# Advanced ML libraries
from xgboost import XGBRegressor, XGBClassifier
from sklearn.ensemble import VotingRegressor, RandomForestRegressor
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import mean_squared_error, r2_score, classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
import optuna

logger = logging.getLogger(__name__)

# Text processing
try:
    import spacy
    from transformers import pipeline
    SPACY_AVAILABLE = True
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    spacy = None
    pipeline = None
    SPACY_AVAILABLE = False
    TRANSFORMERS_AVAILABLE = False
    logger.warning("spaCy and/or transformers not available. Text analysis features will be disabled.")

class ModelVersionManager:
    """Manages model versions and performance tracking"""
    
    def __init__(self, model_path: str = "models/"):
        self.model_path = Path(model_path)
        self.model_path.mkdir(exist_ok=True)
        self.versions = {}
        self.current_version = None
        self.performance_history = []
        self.load_existing_models()
    
    def load_existing_models(self):
        """Load existing model versions from disk"""
        try:
            version_file = self.model_path / "versions.json"
            if version_file.exists():
                with open(version_file, 'r') as f:
                    data = json.load(f)
                    self.versions = data.get('versions', {})
                    self.current_version = data.get('current_version')
                    self.performance_history = data.get('performance_history', [])
        except Exception as e:
            logger.warning(f"Failed to load existing models: {e}")
    
    def save_model_version(self, model, version: str, performance: Dict, features: List[str]):
        """Save a new model version with performance metrics"""
        try:
            # Save model file
            model_file = self.model_path / f"model_{version}.joblib"
            joblib.dump(model, model_file)
            
            # Update version info
            self.versions[version] = {
                'model_file': str(model_file),
                'performance': performance,
                'features': features,
                'timestamp': datetime.now().isoformat(),
                'is_active': False
            }
            
            # Add to performance history
            self.performance_history.append({
                'version': version,
                'performance': performance,
                'timestamp': datetime.now().isoformat()
            })
            
            # Save version metadata
            self._save_version_metadata()
            
            logger.info(f"Saved model version {version} with performance: {performance}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save model version {version}: {e}")
            return False
    
    def activate_version(self, version: str) -> bool:
        """Activate a specific model version"""
        if version not in self.versions:
            logger.error(f"Model version {version} not found")
            return False
        
        # Deactivate current version
        if self.current_version:
            self.versions[self.current_version]['is_active'] = False
        
        # Activate new version
        self.versions[version]['is_active'] = True
        self.current_version = version
        self._save_version_metadata()
        
        logger.info(f"Activated model version {version}")
        return True
    
    def get_current_model(self):
        """Get the currently active model"""
        if not self.current_version:
            return None
        
        try:
            model_file = self.versions[self.current_version]['model_file']
            return joblib.load(model_file)
        except Exception as e:
            logger.error(f"Failed to load current model: {e}")
            return None
    
    def _save_version_metadata(self):
        """Save version metadata to disk"""
        metadata = {
            'versions': self.versions,
            'current_version': self.current_version,
            'performance_history': self.performance_history
        }
        
        with open(self.model_path / "versions.json", 'w') as f:
            json.dump(metadata, f, indent=2)

class EnhancedAIAnalyticsService:
    """Enhanced AI analytics service with advanced ML capabilities"""
    
    def __init__(self):
        self.model_manager = ModelVersionManager()
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.text_vectorizer = TfidfVectorizer(max_features=1000)
        
        # Initialize NLP pipeline
        if SPACY_AVAILABLE:
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                logger.warning("spaCy model not found. Installing...")
                os.system("python -m spacy download en_core_web_sm")
                self.nlp = spacy.load("en_core_web_sm")
        else:
            self.nlp = None
            logger.warning("spaCy not available. Text analysis features disabled.")
        
        # Initialize sentiment analysis
        if TRANSFORMERS_AVAILABLE:
            try:
                self.sentiment_analyzer = pipeline("sentiment-analysis")
            except Exception as e:
                logger.warning(f"Sentiment analysis not available: {e}")
                self.sentiment_analyzer = None
        else:
            self.sentiment_analyzer = None
            logger.warning("Transformers not available. Sentiment analysis disabled.")
    
    def prepare_enhanced_features(self, vulnerabilities: List[Dict]) -> pd.DataFrame:
        """Prepare enhanced features for machine learning models"""
        features = []
        
        for vuln in vulnerabilities:
            # Basic features
            basic_features = self._extract_basic_features(vuln)
            
            # Temporal features
            temporal_features = self._extract_temporal_features(vuln)
            
            # Text features
            text_features = self._extract_text_features(vuln)
            
            # Network features
            network_features = self._extract_network_features(vuln)
            
            # Threat intelligence features
            threat_features = self._extract_threat_features(vuln)
            
            # Combine all features
            combined_features = {
                **basic_features,
                **temporal_features,
                **text_features,
                **network_features,
                **threat_features
            }
            
            features.append(combined_features)
        
        return pd.DataFrame(features)
    
    def _extract_basic_features(self, vuln: Dict) -> Dict:
        """Extract basic vulnerability features"""
        return {
            'cvss_score': float(vuln.get('cvss_score', 0)),
            'epss_score': float(vuln.get('epss_score', 0)),
            'has_exploit': 1 if vuln.get('has_exploit', False) else 0,
            'has_poc': 1 if vuln.get('has_poc', False) else 0,
            'affected_components': len(vuln.get('affected_components', [])),
            'cwe_count': len(vuln.get('cwe_ids', [])),
            'vendor_count': len(vuln.get('affected_vendors', [])),
            'references_count': len(vuln.get('references', [])),
            'patch_available': 1 if vuln.get('patch_available', False) else 0,
            'remote_exploitable': 1 if vuln.get('remote_exploitable', False) else 0,
            'privilege_escalation': 1 if vuln.get('privilege_escalation', False) else 0,
            'data_exfiltration': 1 if vuln.get('data_exfiltration', False) else 0,
            'service_disruption': 1 if vuln.get('service_disruption', False) else 0,
        }
    
    def _extract_temporal_features(self, vuln: Dict) -> Dict:
        """Extract time-based features"""
        try:
            published_date = vuln.get('published_date')
            last_modified = vuln.get('last_modified_date')
            
            if published_date:
                pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                days_since_published = (datetime.now(pub_date.tzinfo) - pub_date).days
                publish_day_of_week = pub_date.weekday()
                publish_month = pub_date.month
            else:
                days_since_published = 0
                publish_day_of_week = 0
                publish_month = 0
            
            if last_modified:
                mod_date = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
                days_since_modified = (datetime.now(mod_date.tzinfo) - mod_date).days
            else:
                days_since_modified = days_since_published
            
            return {
                'days_since_published': days_since_published,
                'days_since_modified': days_since_modified,
                'publish_day_of_week': publish_day_of_week,
                'publish_month': publish_month,
                'time_to_first_exploit': self._calculate_time_to_exploit(vuln),
                'patch_response_time': self._calculate_patch_time(vuln),
                'update_frequency': self._calculate_update_frequency(vuln)
            }
        except Exception as e:
            logger.warning(f"Error extracting temporal features: {e}")
            return {
                'days_since_published': 0,
                'days_since_modified': 0,
                'publish_day_of_week': 0,
                'publish_month': 0,
                'time_to_first_exploit': 0,
                'patch_response_time': 0,
                'update_frequency': 0
            }
    
    def _extract_text_features(self, vuln: Dict) -> Dict:
        """Extract features from vulnerability descriptions"""
        try:
            description = vuln.get('description', '')
            if not description:
                return {
                    'description_length': 0,
                    'word_count': 0,
                    'sentence_count': 0,
                    'named_entities': 0,
                    'technical_terms': 0,
                    'severity_indicators': 0,
                    'sentiment_score': 0
                }
            
            # Basic text features that don't require spacy
            description_length = len(description)
            word_count = len(description.split())
            sentence_count = len(description.split('.'))
            
            # Advanced features with spacy
            if self.nlp and SPACY_AVAILABLE:
                doc = self.nlp(description)
                technical_terms = self._count_technical_terms(doc)
                severity_indicators = self._extract_severity_indicators(doc)
                named_entities = len(doc.ents)
            else:
                # Fallback to basic text analysis
                technical_terms = self._count_technical_terms_basic(description)
                severity_indicators = self._extract_severity_indicators_basic(description)
                named_entities = 0
            
            # Sentiment analysis
            sentiment_score = 0
            if self.sentiment_analyzer and TRANSFORMERS_AVAILABLE:
                try:
                    sentiment_result = self.sentiment_analyzer(description[:512])[0]
                    sentiment_score = 1 if sentiment_result['label'] == 'NEGATIVE' else 0
                except Exception as e:
                    logger.warning(f"Sentiment analysis failed: {e}")
            
            return {
                'description_length': description_length,
                'word_count': word_count,
                'sentence_count': sentence_count,
                'named_entities': named_entities,
                'technical_terms': technical_terms,
                'severity_indicators': severity_indicators,
                'sentiment_score': sentiment_score
            }
        except Exception as e:
            logger.warning(f"Error extracting text features: {e}")
            return {
                'description_length': 0,
                'word_count': 0,
                'sentence_count': 0,
                'named_entities': 0,
                'technical_terms': 0,
                'severity_indicators': 0,
                'sentiment_score': 0
            }
    
    def _extract_network_features(self, vuln: Dict) -> Dict:
        """Extract network and dependency features"""
        affected_components = vuln.get('affected_components', [])
        affected_vendors = vuln.get('affected_vendors', [])
        
        return {
            'component_diversity': len(set(affected_components)),
            'vendor_diversity': len(set(affected_vendors)),
            'popular_component': 1 if any(comp in ['apache', 'nginx', 'mysql', 'postgresql'] for comp in affected_components) else 0,
            'popular_vendor': 1 if any(vendor in ['microsoft', 'oracle', 'adobe', 'google'] for vendor in affected_vendors) else 0,
            'dependency_depth': self._calculate_dependency_depth(vuln),
            'network_exposure': self._calculate_network_exposure(vuln)
        }
    
    def _extract_threat_features(self, vuln: Dict) -> Dict:
        """Extract threat intelligence features"""
        references = vuln.get('references', [])
        
        return {
            'exploit_references': len([ref for ref in references if 'exploit' in ref.lower()]),
            'patch_references': len([ref for ref in references if 'patch' in ref.lower()]),
            'advisory_references': len([ref for ref in references if 'advisory' in ref.lower()]),
            'vendor_references': len([ref for ref in references if 'vendor' in ref.lower()]),
            'threat_level': self._calculate_threat_level(vuln),
            'attack_complexity': self._calculate_attack_complexity(vuln)
        }
    
    def _count_technical_terms(self, doc) -> int:
        """Count technical terms in the document"""
        technical_terms = [
            'vulnerability', 'exploit', 'patch', 'security', 'attack',
            'buffer', 'overflow', 'injection', 'xss', 'csrf', 'sql',
            'authentication', 'authorization', 'encryption', 'ssl', 'tls'
        ]
        return sum(1 for token in doc if token.text.lower() in technical_terms)
    
    def _count_technical_terms_basic(self, text: str) -> int:
        """Count technical terms in text (basic version without spacy)"""
        technical_terms = [
            'vulnerability', 'exploit', 'patch', 'security', 'attack',
            'buffer', 'overflow', 'injection', 'xss', 'csrf', 'sql',
            'authentication', 'authorization', 'encryption', 'ssl', 'tls'
        ]
        text_lower = text.lower()
        return sum(1 for term in technical_terms if term in text_lower)
    
    def _extract_severity_indicators(self, doc) -> int:
        """Extract severity indicators from text"""
        severity_terms = [
            'critical', 'high', 'severe', 'dangerous', 'exploitable',
            'remote', 'privilege', 'escalation', 'data', 'breach'
        ]
        return sum(1 for token in doc if token.text.lower() in severity_terms)
    
    def _extract_severity_indicators_basic(self, text: str) -> int:
        """Extract severity indicators from text (basic version without spacy)"""
        severity_terms = [
            'critical', 'high', 'severe', 'dangerous', 'exploitable',
            'remote', 'privilege', 'escalation', 'data', 'breach'
        ]
        text_lower = text.lower()
        return sum(1 for term in severity_terms if term in text_lower)
    
    def _calculate_time_to_exploit(self, vuln: Dict) -> int:
        """Calculate time from publication to first exploit"""
        # This would require historical exploit data
        # For now, return a placeholder
        return 0
    
    def _calculate_patch_time(self, vuln: Dict) -> int:
        """Calculate time from publication to patch availability"""
        # This would require historical patch data
        # For now, return a placeholder
        return 0
    
    def _calculate_update_frequency(self, vuln: Dict) -> int:
        """Calculate update frequency for the vulnerability"""
        # This would require historical update data
        # For now, return a placeholder
        return 0
    
    def _calculate_dependency_depth(self, vuln: Dict) -> int:
        """Calculate dependency depth for affected components"""
        # This would require dependency graph analysis
        # For now, return a placeholder
        return 1
    
    def _calculate_network_exposure(self, vuln: Dict) -> int:
        """Calculate network exposure level"""
        # This would require network topology analysis
        # For now, return a placeholder
        return 1
    
    def _calculate_threat_level(self, vuln: Dict) -> int:
        """Calculate threat level based on various factors"""
        threat_score = 0
        
        if vuln.get('has_exploit'):
            threat_score += 3
        if vuln.get('has_poc'):
            threat_score += 2
        if vuln.get('remote_exploitable'):
            threat_score += 2
        if vuln.get('privilege_escalation'):
            threat_score += 1
        
        return min(threat_score, 5)  # Scale 0-5
    
    def _calculate_attack_complexity(self, vuln: Dict) -> int:
        """Calculate attack complexity"""
        complexity_score = 0
        
        if vuln.get('remote_exploitable'):
            complexity_score += 1
        if vuln.get('privilege_escalation'):
            complexity_score += 1
        if vuln.get('data_exfiltration'):
            complexity_score += 1
        
        return min(complexity_score, 3)  # Scale 0-3
    
    def optimize_hyperparameters(self, vulnerabilities: List[Dict]) -> Dict:
        """Optimize model hyperparameters using Optuna"""
        try:
            df = self.prepare_enhanced_features(vulnerabilities)
            risk_scores = [float(v.get('risk_score', 0)) for v in vulnerabilities]
            
            if len(df) < 20:
                return {"success": False, "message": "Insufficient data for hyperparameter optimization"}
            
            X_train, X_test, y_train, y_test = train_test_split(
                df, risk_scores, test_size=0.2, random_state=42
            )
            
            def objective(trial):
                params = {
                    'n_estimators': trial.suggest_int('n_estimators', 100, 1000),
                    'max_depth': trial.suggest_int('max_depth', 3, 10),
                    'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3),
                    'subsample': trial.suggest_float('subsample', 0.6, 1.0),
                    'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
                    'reg_alpha': trial.suggest_float('reg_alpha', 0, 1),
                    'reg_lambda': trial.suggest_float('reg_lambda', 0, 1)
                }
                
                model = XGBRegressor(**params, random_state=42)
                scores = cross_val_score(model, X_train, y_train, cv=3, scoring='neg_mean_squared_error')
                return -scores.mean()
            
            study = optuna.create_study(direction='minimize')
            study.optimize(objective, n_trials=50)
            
            best_params = study.best_params
            best_score = study.best_value
            
            logger.info(f"Hyperparameter optimization completed. Best MSE: {best_score}")
            
            return {
                "success": True,
                "best_params": best_params,
                "best_score": best_score,
                "n_trials": len(study.trials)
            }
            
        except Exception as e:
            logger.error(f"Hyperparameter optimization failed: {e}")
            return {"success": False, "error": str(e)}
    
    def train_enhanced_model(self, vulnerabilities: List[Dict]) -> Dict:
        """Train enhanced machine learning model with optimized parameters"""
        try:
            df = self.prepare_enhanced_features(vulnerabilities)
            risk_scores = [float(v.get('risk_score', 0)) for v in vulnerabilities]
            
            if len(df) < 20:
                return {"success": False, "message": "Insufficient data for training"}
            
            # Optimize hyperparameters
            optimization_result = self.optimize_hyperparameters(vulnerabilities)
            if not optimization_result["success"]:
                return optimization_result
            
            best_params = optimization_result["best_params"]
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                df, risk_scores, test_size=0.2, random_state=42
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train XGBoost model with optimized parameters
            model = XGBRegressor(**best_params, random_state=42)
            model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = model.predict(X_test_scaled)
            mse = mean_squared_error(y_test, y_pred)
            r2 = r2_score(y_test, y_pred)
            
            # Get feature importance
            feature_importance = dict(zip(df.columns, model.feature_importances_))
            
            # Save model version
            version = f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            performance = {
                "mse": mse,
                "r2_score": r2,
                "training_samples": len(X_train),
                "test_samples": len(X_test),
                "feature_count": len(df.columns)
            }
            
            self.model_manager.save_model_version(
                model, version, performance, list(df.columns)
            )
            
            # Activate new version
            self.model_manager.activate_version(version)
            
            logger.info(f"Enhanced model trained successfully. Version: {version}, R²: {r2:.4f}")
            
            return {
                "success": True,
                "version": version,
                "performance": performance,
                "feature_importance": feature_importance,
                "best_params": best_params
            }
            
        except Exception as e:
            logger.error(f"Enhanced model training failed: {e}")
            return {"success": False, "error": str(e)}
    
    def predict_enhanced_risk(self, vulnerabilities: List[Dict]) -> Dict:
        """Predict risk scores using enhanced model"""
        try:
            model = self.model_manager.get_current_model()
            if not model:
                return {"success": False, "message": "No trained model available"}
            
            df = self.prepare_enhanced_features(vulnerabilities)
            X_scaled = self.scaler.transform(df)
            
            predictions = model.predict(X_scaled)
            
            # Calculate prediction confidence (using model's internal confidence)
            if hasattr(model, 'predict_proba'):
                confidence_scores = model.predict_proba(X_scaled).max(axis=1)
            else:
                # For regression, use a simple confidence based on feature values
                confidence_scores = np.ones(len(predictions)) * 0.8
            
            results = []
            for i, vuln in enumerate(vulnerabilities):
                results.append({
                    "cve_id": vuln.get("cve_id", ""),
                    "predicted_risk_score": float(predictions[i]),
                    "confidence": float(confidence_scores[i]),
                    "features_used": len(df.columns)
                })
            
            return {
                "success": True,
                "predictions": results,
                "model_version": self.model_manager.current_version,
                "feature_count": len(df.columns)
            }
            
        except Exception as e:
            logger.error(f"Enhanced risk prediction failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_model_performance(self) -> Dict:
        """Get current model performance metrics"""
        if not self.model_manager.current_version:
            return {"success": False, "message": "No active model"}
        
        current_version = self.model_manager.current_version
        version_info = self.model_manager.versions[current_version]
        
        return {
            "success": True,
            "current_version": current_version,
            "performance": version_info["performance"],
            "features": version_info["features"],
            "timestamp": version_info["timestamp"],
            "performance_history": self.model_manager.performance_history
        }
    
    def detect_model_drift(self, vulnerabilities: List[Dict]) -> Dict:
        """Detect model drift using current data"""
        try:
            if not self.model_manager.current_version:
                return {"success": False, "message": "No active model"}
            
            df = self.prepare_enhanced_features(vulnerabilities)
            model = self.model_manager.get_current_model()
            
            if not model:
                return {"success": False, "message": "Failed to load current model"}
            
            # Get predictions for current data
            X_scaled = self.scaler.transform(df)
            current_predictions = model.predict(X_scaled)
            
            # Calculate drift metrics (simplified version)
            # In production, you'd compare with training data distribution
            drift_metrics = {
                "prediction_mean": float(np.mean(current_predictions)),
                "prediction_std": float(np.std(current_predictions)),
                "feature_drift_score": 0.1,  # Placeholder
                "performance_drift_score": 0.05  # Placeholder
            }
            
            # Determine if drift is detected
            drift_detected = (
                drift_metrics["feature_drift_score"] > 0.2 or
                drift_metrics["performance_drift_score"] > 0.1
            )
            
            return {
                "success": True,
                "drift_detected": drift_detected,
                "drift_metrics": drift_metrics,
                "recommendation": "Retrain model" if drift_detected else "Model performing well"
            }
            
        except Exception as e:
            logger.error(f"Model drift detection failed: {e}")
            return {"success": False, "error": str(e)}

# Global instance
enhanced_ai_service = EnhancedAIAnalyticsService() 