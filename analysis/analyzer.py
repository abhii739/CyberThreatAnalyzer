"""
Security Analysis Module
Analyzes cybersecurity logs and detects attack patterns
"""
import pandas as pd
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import config

class SecurityAnalyzer:
    """Analyzes security logs for attack patterns and threats"""
    
    def __init__(self, logs_dataframe):
        """
        Initialize analyzer with logs dataframe
        
        Args:
            logs_dataframe: Pandas DataFrame containing log data
        """
        self.df = logs_dataframe
        self.analysis_results = {}
    
    def analyze_all(self):
        """Run all analyses"""
        self.analysis_results = {
            'total_logs': len(self.df),
            'total_attacks': self.count_total_attacks(),
            'failed_logins': self.count_failed_logins(),
            'brute_force_attempts': self.detect_brute_force(),
            'port_scans': self.detect_port_scans(),
            'daily_attack_count': self.get_daily_attack_count(),
            'monthly_attack_trend': self.get_monthly_attack_trend(),
            'top_attacking_ips': self.get_top_attacking_ips(),
            'top_targeted_users': self.get_top_targeted_users(),
            'attack_type_distribution': self.get_attack_type_distribution(),
            'top_countries': self.get_top_countries(),
            'protocol_usage': self.get_protocol_usage(),
            'success_vs_failed_ratio': self.get_success_vs_failed_ratio(),
            'risk_analysis': self.calculate_risk_scores(),
            'suspicious_countries': self.get_suspicious_countries(),
        }
        return self.analysis_results
    
    def count_total_attacks(self):
        """Count total number of attacks"""
        return len(self.df)
    
    def count_failed_logins(self):
        """Count failed login attempts"""
        if self.df.empty:
            return 0
        failed = self.df[self.df['Status'].str.lower() == 'failed']
        return len(failed)
    
    def detect_brute_force(self):
        """Detect brute force attacks"""
        if self.df.empty:
            return []
        
        failed_attempts = self.df[self.df['Status'].str.lower() == 'failed']
        ip_attempt_counts = failed_attempts['Source_IP'].value_counts()
        
        brute_force_ips = ip_attempt_counts[
            ip_attempt_counts >= config.BRUTE_FORCE_THRESHOLD
        ].to_dict()
        
        return brute_force_ips
    
    def detect_port_scans(self):
        """Detect port scanning activities"""
        if self.df.empty:
            return []
        
        ip_port_counts = self.df.groupby('Source_IP')['Port'].nunique()
        port_scans = ip_port_counts[
            ip_port_counts >= config.PORT_SCAN_THRESHOLD
        ].to_dict()
        
        return port_scans
    
    def get_daily_attack_count(self):
        """Get daily attack count"""
        if self.df.empty:
            return {}
        
        self.df['Date'] = pd.to_datetime(self.df['Timestamp']).dt.date
        daily_counts = self.df.groupby('Date').size().to_dict()
        
        return {str(k): v for k, v in sorted(daily_counts.items())}
    
    def get_monthly_attack_trend(self):
        """Get monthly attack trend"""
        if self.df.empty:
            return {}
        
        self.df['YearMonth'] = pd.to_datetime(self.df['Timestamp']).dt.to_period('M')
        monthly_counts = self.df.groupby('YearMonth').size().to_dict()
        
        return {str(k): v for k, v in sorted(monthly_counts.items())}
    
    def get_top_attacking_ips(self, limit=10):
        """Get top attacking IPs"""
        if self.df.empty:
            return {}
        
        ip_counts = self.df['Source_IP'].value_counts().head(limit)
        return ip_counts.to_dict()
    
    def get_top_targeted_users(self, limit=10):
        """Get top targeted users"""
        if self.df.empty:
            return {}
        
        user_counts = self.df['Username'].value_counts().head(limit)
        return user_counts.to_dict()
    
    def get_attack_type_distribution(self):
        """Get attack type distribution"""
        if self.df.empty:
            return {}
        
        attack_dist = self.df['Attack_Type'].value_counts().to_dict()
        return attack_dist
    
    def get_top_countries(self, limit=10):
        """Get top attacking countries"""
        if self.df.empty:
            return {}
        
        country_counts = self.df['Country'].value_counts().head(limit)
        return country_counts.to_dict()
    
    def get_protocol_usage(self):
        """Get protocol usage statistics"""
        if self.df.empty:
            return {}
        
        protocol_counts = self.df['Protocol'].value_counts().to_dict()
        return protocol_counts
    
    def get_success_vs_failed_ratio(self):
        """Get success vs failed login ratio"""
        if self.df.empty:
            return {'success': 0, 'failed': 0}
        
        success = len(self.df[self.df['Status'].str.lower() == 'success'])
        failed = len(self.df[self.df['Status'].str.lower() == 'failed'])
        
        return {'success': success, 'failed': failed}
    
    def calculate_risk_scores(self, limit=10):
        """Calculate risk scores for IPs"""
        if self.df.empty:
            return {}
        
        risk_scores = {}
        
        # Get all unique IPs
        ips = self.df['Source_IP'].unique()
        
        for ip in ips:
            ip_logs = self.df[self.df['Source_IP'] == ip]
            score = 0
            risk_level = 'Low'
            
            # Brute force detection
            failed_count = len(ip_logs[ip_logs['Status'].str.lower() == 'failed'])
            if failed_count >= config.BRUTE_FORCE_THRESHOLD:
                score += 40
            elif failed_count >= 5:
                score += 20
            
            # Port scanning detection
            unique_ports = ip_logs['Port'].nunique()
            if unique_ports >= config.PORT_SCAN_THRESHOLD:
                score += 30
            elif unique_ports >= 10:
                score += 15
            
            # Attack type severity
            attack_types = ip_logs['Attack_Type'].value_counts().to_dict()
            if 'Brute Force' in attack_types:
                score += 20
            if 'DDoS' in attack_types:
                score += 25
            if 'SQL Injection' in attack_types:
                score += 30
            
            # Multiple failed attempts from same IP
            if failed_count > 0:
                score += min(failed_count * 2, 20)
            
            # Determine risk level
            if score >= 80:
                risk_level = 'Critical'
            elif score >= 60:
                risk_level = 'High'
            elif score >= 40:
                risk_level = 'Medium'
            else:
                risk_level = 'Low'
            
            risk_scores[ip] = {
                'score': min(score, 100),
                'level': risk_level,
                'reasons': self._get_risk_reasons(ip_logs, failed_count, unique_ports)
            }
        
        # Sort by score and limit
        sorted_scores = sorted(
            risk_scores.items(),
            key=lambda x: x[1]['score'],
            reverse=True
        )[:limit]
        
        return dict(sorted_scores)
    
    def _get_risk_reasons(self, ip_logs, failed_count, unique_ports):
        """Get reasons for risk score"""
        reasons = []
        
        if failed_count >= config.BRUTE_FORCE_THRESHOLD:
            reasons.append(f'Brute force attack detected ({failed_count} failed attempts)')
        
        if unique_ports >= config.PORT_SCAN_THRESHOLD:
            reasons.append(f'Port scanning detected ({unique_ports} different ports)')
        
        attack_types = ip_logs['Attack_Type'].unique()
        if len(attack_types) > 1:
            reasons.append(f'Multiple attack types: {", ".join(attack_types[:3])}')
        
        return reasons
    
    def get_suspicious_countries(self):
        """Get suspicious countries with unusual activity"""
        if self.df.empty:
            return {}
        
        country_counts = self.df['Country'].value_counts().to_dict()
        suspicious = {k: v for k, v in country_counts.items() if k.lower() in ['unknown', 'vpn', 'proxy']}
        
        return suspicious
    
    def get_statistics(self):
        """Get comprehensive statistics"""
        if self.df.empty:
            return {
                'total_logs': 0,
                'total_attacks': 0,
                'failed_logins': 0,
                'unique_ips': 0,
                'unique_users': 0,
                'unique_countries': 0,
                'unique_attack_types': 0,
                'critical_threats': 0,
                'high_risk_ips': 0,
            }
        
        risk_scores = self.calculate_risk_scores(limit=100)
        critical = sum(1 for r in risk_scores.values() if r['level'] == 'Critical')
        high = sum(1 for r in risk_scores.values() if r['level'] == 'High')
        
        return {
            'total_logs': len(self.df),
            'total_attacks': self.count_total_attacks(),
            'failed_logins': self.count_failed_logins(),
            'unique_ips': self.df['Source_IP'].nunique(),
            'unique_users': self.df['Username'].nunique(),
            'unique_countries': self.df['Country'].nunique(),
            'unique_attack_types': self.df['Attack_Type'].nunique(),
            'critical_threats': critical,
            'high_risk_ips': high,
        }
