"""
Database Helper - Query functions for findings database
Provides easy access to stored security findings
"""
from sqlalchemy import create_engine, and_, or_, desc
from sqlalchemy.orm import sessionmaker
from storage.models import Base, Finding
from datetime import datetime, timedelta


class DatabaseHelper:
    """Helper class for database operations"""
    
    def __init__(self, db_path="storage/acase.db"):
        self.engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def add_finding(self, target, finding_type, evidence, risk_level="MEDIUM"):
        """Add a new finding to database"""
        finding = Finding(
            target=target,
            finding_type=finding_type,
            evidence=evidence,
            risk_level=risk_level,
            timestamp=datetime.now()
        )
        self.session.add(finding)
        self.session.commit()
        return finding.id
    
    def get_all_findings(self):
        """Get all findings"""
        return self.session.query(Finding).all()
    
    def get_findings_by_target(self, target):
        """Get all findings for a specific target"""
        return self.session.query(Finding).filter(Finding.target == target).all()
    
    def get_findings_by_risk(self, risk_level):
        """Get findings by risk level (HIGH, MEDIUM, LOW)"""
        return self.session.query(Finding).filter(Finding.risk_level == risk_level).all()
    
    def get_findings_by_type(self, finding_type):
        """Get findings by type (e.g., 'username_enum', 'weak_session')"""
        return self.session.query(Finding).filter(Finding.finding_type == finding_type).all()
    
    def get_recent_findings(self, hours=24):
        """Get findings from last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return self.session.query(Finding).filter(Finding.timestamp >= cutoff).all()
    
    def get_high_risk_findings(self):
        """Get all HIGH and CRITICAL risk findings"""
        return self.session.query(Finding).filter(
            or_(Finding.risk_level == "HIGH", Finding.risk_level == "CRITICAL")
        ).all()
    
    def get_findings_count_by_target(self, target):
        """Count findings for a target"""
        return self.session.query(Finding).filter(Finding.target == target).count()
    
    def get_findings_summary(self):
        """Get summary statistics"""
        all_findings = self.get_all_findings()
        
        summary = {
            "total": len(all_findings),
            "by_risk": {},
            "by_type": {},
            "by_target": {}
        }
        
        for finding in all_findings:
            risk = finding.risk_level
            summary["by_risk"][risk] = summary["by_risk"].get(risk, 0) + 1
            ftype = finding.finding_type
            summary["by_type"][ftype] = summary["by_type"].get(ftype, 0) + 1
            target = finding.target
            summary["by_target"][target] = summary["by_target"].get(target, 0) + 1
        
        return summary
    
    def search_findings(self, keyword):
        """Search findings by keyword in evidence or type"""
        return self.session.query(Finding).filter(
            or_(
                Finding.evidence.contains(keyword),
                Finding.finding_type.contains(keyword)
            )
        ).all()
    
    def delete_finding(self, finding_id):
        """Delete a finding by ID"""
        finding = self.session.query(Finding).filter(Finding.id == finding_id).first()
        if finding:
            self.session.delete(finding)
            self.session.commit()
            return True
        return False
    
    def delete_findings_by_target(self, target):
        """Delete all findings for a target"""
        count = self.session.query(Finding).filter(Finding.target == target).delete()
        self.session.commit()
        return count
    
    def get_latest_scan(self, target):
        """Get most recent finding for a target"""
        return self.session.query(Finding).filter(
            Finding.target == target
        ).order_by(desc(Finding.timestamp)).first()
    
    def export_to_dict(self, target=None):
        """Export findings to dictionary format"""
        if target:
            findings = self.get_findings_by_target(target)
        else:
            findings = self.get_all_findings()
        
        return [
            {
                "id": f.id,
                "target": f.target,
                "type": f.finding_type,
                "evidence": f.evidence,
                "risk": f.risk_level,
                "timestamp": f.timestamp.isoformat()
            }
            for f in findings
        ]
    
    def close(self):
        """Close database session"""
        self.session.close()


def get_db():
    """Get database helper instance"""
    return DatabaseHelper()


def quick_add(target, finding_type, evidence, risk="MEDIUM"):
    """Quick add a finding"""
    db = get_db()
    finding_id = db.add_finding(target, finding_type, evidence, risk)
    db.close()
    return finding_id


def quick_search(keyword):
    """Quick search findings"""
    db = get_db()
    results = db.search_findings(keyword)
    db.close()
    return results


def quick_summary():
    """Quick get summary"""
    db = get_db()
    summary = db.get_findings_summary()
    db.close()
    return summary
