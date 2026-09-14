import sqlite3
import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

class DatabaseManager:
    def __init__(self, db_path: str = "vulnrisk.db"):
        # Detect if running in AWS Lambda environment
        self.is_lambda = bool(os.getenv('AWS_LAMBDA_FUNCTION_NAME'))
        
        if self.is_lambda:
            # Production: Use DynamoDB
            import boto3
            self.use_dynamodb = True
            self.dynamodb = boto3.resource('dynamodb')
            self.table_name = os.getenv('DYNAMODB_TABLE', 'vulnrisk-vulnerabilities')
            self.table = self.dynamodb.Table(self.table_name)
            print(f"DatabaseManager: Using DynamoDB table '{self.table_name}' (Lambda environment detected)")
            print(f"DatabaseManager: AWS_LAMBDA_FUNCTION_NAME = {os.getenv('AWS_LAMBDA_FUNCTION_NAME')}")
        else:
            # Development: Use SQLite
            self.use_dynamodb = False
            self.db_path = db_path
            self.init_database()
            print(f"DatabaseManager: Using SQLite database '{self.db_path}' (development environment)")
    
    def init_database(self):
        """Initialize the database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create risk assessments table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS risk_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    priority TEXT NOT NULL,
                    timeline_days INTEGER NOT NULL,
                    explanation TEXT NOT NULL,
                    components TEXT NOT NULL,
                    asset_criticality INTEGER NOT NULL,
                    is_internet_facing BOOLEAN NOT NULL,
                    framework TEXT NOT NULL,
                    user_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    -- Federal-specific fields for VDR Standard
                    service_degradation_hours REAL,
                    federal_data_exposure_percentage REAL,
                    estimated_downtime_hours REAL,
                    affected_users_percentage REAL,
                    -- VDR classification fields
                    impact_rating TEXT,
                    lev_status BOOLEAN,
                    irv_status BOOLEAN,
                    timeline_category TEXT,
                    incident_response_required BOOLEAN,
                    context_factors TEXT,
                    compliance_report TEXT
                )
            ''')
            
            # Create user sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                )
            ''')
            
            # Create batch jobs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS batch_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT UNIQUE NOT NULL,
                    user_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    total_vulnerabilities INTEGER NOT NULL,
                    processed_vulnerabilities INTEGER DEFAULT 0,
                    results TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP
                )
            ''')
            
            conn.commit()
    
    def save_risk_assessment(self, assessment_data: Dict[str, Any], user_id: Optional[str] = None) -> str:
        """Save a risk assessment result to the database"""
        if self.use_dynamodb:
            # DynamoDB implementation
            item_id = str(uuid.uuid4())
            item = {
                'id': item_id,
                'type': 'risk_assessment',
                'cve_id': assessment_data['cve_id'],
                'risk_score': assessment_data['risk_score'],
                'priority': assessment_data['priority'],
                'timeline_days': assessment_data['timeline_days'],
                'explanation': assessment_data['explanation'],
                'components': assessment_data['components'],  # DynamoDB handles JSON natively
                'asset_criticality': assessment_data['asset_criticality'],
                'is_internet_facing': assessment_data['is_internet_facing'],
                'framework': assessment_data['framework'],
                'user_id': user_id or 'anonymous',
                'created_at': datetime.utcnow().isoformat(),
                # Federal-specific fields
                'service_degradation_hours': assessment_data.get('service_degradation_hours'),
                'federal_data_exposure_percentage': assessment_data.get('federal_data_exposure_percentage'),
                'estimated_downtime_hours': assessment_data.get('estimated_downtime_hours'),
                'affected_users_percentage': assessment_data.get('affected_users_percentage'),
                # VDR classification fields
                'impact_rating': assessment_data.get('impact_rating'),
                'lev_status': assessment_data.get('lev_status'),
                'irv_status': assessment_data.get('irv_status'),
                'timeline_category': assessment_data.get('timeline_category'),
                'incident_response_required': assessment_data.get('incident_response_required'),
                'context_factors': assessment_data.get('context_factors'),
                'compliance_report': assessment_data.get('compliance_report')
            }
            
            self.table.put_item(Item=item)
            return item_id
        else:
            # SQLite implementation
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO risk_assessments (
                        cve_id, risk_score, priority, timeline_days, explanation,
                        components, asset_criticality, is_internet_facing, framework, user_id,
                        service_degradation_hours, federal_data_exposure_percentage, 
                        estimated_downtime_hours, affected_users_percentage,
                        impact_rating, lev_status, irv_status, timeline_category,
                        incident_response_required, context_factors, compliance_report
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    assessment_data['cve_id'],
                    assessment_data['risk_score'],
                    assessment_data['priority'],
                    assessment_data['timeline_days'],
                    assessment_data['explanation'],
                    json.dumps(assessment_data['components']),
                    assessment_data['asset_criticality'],
                    assessment_data['is_internet_facing'],
                    assessment_data['framework'],
                    user_id,
                    # Federal-specific fields
                    assessment_data.get('service_degradation_hours'),
                    assessment_data.get('federal_data_exposure_percentage'),
                    assessment_data.get('estimated_downtime_hours'),
                    assessment_data.get('affected_users_percentage'),
                    # VDR classification fields
                    assessment_data.get('impact_rating'),
                    assessment_data.get('lev_status'),
                    assessment_data.get('irv_status'),
                    assessment_data.get('timeline_category'),
                    assessment_data.get('incident_response_required'),
                    json.dumps(assessment_data.get('context_factors', {})),
                    json.dumps(assessment_data.get('compliance_report', {}))
                ))
                
                conn.commit()
                return str(cursor.lastrowid)
    
    def get_risk_assessments(self, user_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get risk assessment history"""
        if self.use_dynamodb:
            # DynamoDB implementation
            try:
                if user_id:
                    # Query by user_id and type
                    response = self.table.scan(
                        FilterExpression='#type = :type AND user_id = :user_id',
                        ExpressionAttributeNames={'#type': 'type'},
                        ExpressionAttributeValues={
                            ':type': 'risk_assessment',
                            ':user_id': user_id
                        },
                        Limit=limit
                    )
                else:
                    # Get all risk assessments
                    response = self.table.scan(
                        FilterExpression='#type = :type',
                        ExpressionAttributeNames={'#type': 'type'},
                        ExpressionAttributeValues={':type': 'risk_assessment'},
                        Limit=limit
                    )
                
                items = response.get('Items', [])
                # Sort by created_at descending
                items.sort(key=lambda x: x.get('created_at', ''), reverse=True)
                return items
            except Exception as e:
                print(f"DynamoDB error in get_risk_assessments: {e}")
                return []
        else:
            # SQLite implementation
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if user_id:
                    cursor.execute('''
                        SELECT * FROM risk_assessments 
                        WHERE user_id = ? 
                        ORDER BY created_at DESC 
                        LIMIT ?
                    ''', (user_id, limit))
                else:
                    cursor.execute('''
                        SELECT * FROM risk_assessments 
                        ORDER BY created_at DESC 
                        LIMIT ?
                    ''', (limit,))
                
                rows = cursor.fetchall()
                columns = [description[0] for description in cursor.description]
                
                results = []
                for row in rows:
                    result = dict(zip(columns, row))
                    result['components'] = json.loads(result['components'])
                    results.append(result)
                
                return results
    
    def create_batch_job(self, job_id: str, user_id: str, total_vulnerabilities: int) -> bool:
        """Create a new batch job"""
        if self.use_dynamodb:
            # DynamoDB implementation
            item = {
                'id': job_id,
                'type': 'batch_job',
                'job_id': job_id,
                'user_id': user_id,
                'status': 'processing',
                'total_vulnerabilities': total_vulnerabilities,
                'processed_vulnerabilities': 0,
                'created_at': datetime.utcnow().isoformat()
            }
            self.table.put_item(Item=item)
            return True
        else:
            # SQLite implementation
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO batch_jobs (job_id, user_id, status, total_vulnerabilities)
                    VALUES (?, ?, ?, ?)
                ''', (job_id, user_id, 'processing', total_vulnerabilities))
                
                conn.commit()
                return True
    
    def update_batch_job(self, job_id: str, status: str, processed_count: int = None, results: str = None):
        """Update batch job status"""
        if self.use_dynamodb:
            # DynamoDB implementation
            update_expr = "SET #status = :status"
            expr_attr_names = {"#status": "status"}
            expr_attr_values = {":status": status}
            
            if processed_count is not None:
                update_expr += ", processed_vulnerabilities = :processed"
                expr_attr_values[":processed"] = processed_count
            
            if results is not None:
                update_expr += ", results = :results"
                expr_attr_values[":results"] = results
            
            if status == 'completed':
                update_expr += ", completed_at = :completed_at"
                expr_attr_values[":completed_at"] = datetime.utcnow().isoformat()
            
            self.table.update_item(
                Key={'id': job_id},
                UpdateExpression=update_expr,
                ExpressionAttributeNames=expr_attr_names,
                ExpressionAttributeValues=expr_attr_values
            )
        else:
            # SQLite implementation
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if status == 'completed':
                    cursor.execute('''
                        UPDATE batch_jobs 
                        SET status = ?, processed_vulnerabilities = ?, results = ?, completed_at = CURRENT_TIMESTAMP
                        WHERE job_id = ?
                    ''', (status, processed_count, results, job_id))
                else:
                    cursor.execute('''
                        UPDATE batch_jobs 
                        SET status = ?, processed_vulnerabilities = ?
                        WHERE job_id = ?
                    ''', (status, processed_count, job_id))
                
                conn.commit()
    
    def get_batch_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get batch job details"""
        if self.use_dynamodb:
            # DynamoDB implementation
            try:
                response = self.table.get_item(Key={'id': job_id})
                item = response.get('Item')
                if item and item.get('type') == 'batch_job':
                    return item
                return None
            except Exception as e:
                print(f"DynamoDB error in get_batch_job: {e}")
                return None
        else:
            # SQLite implementation
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM batch_jobs WHERE job_id = ?', (job_id,))
                row = cursor.fetchone()
                
                if row:
                    columns = [description[0] for description in cursor.description]
                    result = dict(zip(columns, row))
                    if result['results']:
                        result['results'] = json.loads(result['results'])
                    return result
                
                return None
    
    def save_user_session(self, user_id: str, session_token: str, expires_at: datetime) -> bool:
        """Save user session"""
        if self.use_dynamodb:
            # DynamoDB implementation
            item = {
                'id': session_token,
                'type': 'user_session',
                'user_id': user_id,
                'session_token': session_token,
                'expires_at': expires_at.isoformat(),
                'created_at': datetime.utcnow().isoformat()
            }
            self.table.put_item(Item=item)
            return True
        else:
            # SQLite implementation
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO user_sessions (user_id, session_token, expires_at)
                    VALUES (?, ?, ?)
                ''', (user_id, session_token, expires_at.isoformat()))
                
                conn.commit()
                return True
    
    def get_user_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Get user session by token"""
        if self.use_dynamodb:
            # DynamoDB implementation
            try:
                response = self.table.get_item(Key={'id': session_token})
                item = response.get('Item')
                if item and item.get('type') == 'user_session':
                    # Check if session is not expired
                    expires_at = datetime.fromisoformat(item['expires_at'])
                    if expires_at > datetime.utcnow():
                        return item
                return None
            except Exception as e:
                print(f"DynamoDB error in get_user_session: {e}")
                return None
        else:
            # SQLite implementation
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM user_sessions 
                    WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP
                ''', (session_token,))
                
                row = cursor.fetchone()
                if row:
                    columns = [description[0] for description in cursor.description]
                    return dict(zip(columns, row))
                
                return None
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        if self.use_dynamodb:
            # DynamoDB implementation - scan for expired sessions and delete them
            try:
                current_time = datetime.utcnow().isoformat()
                response = self.table.scan(
                    FilterExpression='#type = :type AND expires_at < :current_time',
                    ExpressionAttributeNames={'#type': 'type'},
                    ExpressionAttributeValues={
                        ':type': 'user_session',
                        ':current_time': current_time
                    }
                )
                
                for item in response.get('Items', []):
                    self.table.delete_item(Key={'id': item['id']})
            except Exception as e:
                print(f"DynamoDB error in cleanup_expired_sessions: {e}")
        else:
            # SQLite implementation
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('DELETE FROM user_sessions WHERE expires_at <= CURRENT_TIMESTAMP')
                conn.commit()

# Global database instance
db_manager = DatabaseManager() 