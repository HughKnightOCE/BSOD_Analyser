"""
analytics.py
Advanced analytics and pattern detection for BSOD Analyzer
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

class CrashAnalytics:
    """Advanced crash analysis and pattern detection"""
    
    def __init__(self, history_file: Path):
        self.history_file = history_file
        self.history = self._load_history()
    
    def _load_history(self) -> List[Dict]:
        """Load crash history from JSON file"""
        if self.history_file.exists():
            try:
                return json.loads(self.history_file.read_text(encoding="utf-8"))
            except Exception:
                return []
        return []
    
    def save_history(self):
        """Save crash history to JSON file"""
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        self.history_file.write_text(
            json.dumps(self.history, indent=2, default=str),
            encoding="utf-8"
        )
    
    def add_crash(self, crash_data: Dict):
        """Add a new crash to history"""
        crash_data['recorded_at'] = datetime.now().isoformat()
        self.history.append(crash_data)
        # Keep only last 100 crashes
        if len(self.history) > 100:
            self.history = self.history[-100:]
        self.save_history()
    
    def get_crash_frequency(self, days: int = 7) -> Dict:
        """Get crash frequency over last N days"""
        cutoff = datetime.now() - timedelta(days=days)
        recent = []
        for crash in self.history:
            try:
                crash_dt = datetime.fromisoformat(crash.get('TimeLocal', ''))
                if crash_dt > cutoff:
                    recent.append(crash)
            except Exception:
                pass
        
        daily_counts = defaultdict(int)
        for crash in recent:
            try:
                crash_dt = datetime.fromisoformat(crash.get('TimeLocal', ''))
                date_key = crash_dt.date().isoformat()
                daily_counts[date_key] += 1
            except Exception:
                pass
        
        return dict(sorted(daily_counts.items()))
    
    def detect_crash_patterns(self) -> Dict:
        """Detect patterns in crashes"""
        if not self.history:
            return {}
        
        # Stop code patterns
        stop_codes = Counter()
        for crash in self.history:
            code = crash.get('Code', 'UNKNOWN')
            stop_codes[code] += 1
        
        most_common_codes = stop_codes.most_common(5)
        
        # Error patterns (from recent crash data)
        error_providers = Counter()
        for crash in self.history:
            # Would need to parse from raw data
            pass
        
        # Time patterns
        crash_hours = Counter()
        for crash in self.history:
            try:
                crash_dt = datetime.fromisoformat(crash.get('TimeLocal', ''))
                crash_hours[crash_dt.hour] += 1
            except Exception:
                pass
        
        return {
            'most_common_stop_codes': most_common_codes,
            'peak_crash_hours': crash_hours.most_common(3),
            'total_crashes_recorded': len(self.history),
        }
    
    def driver_blame_analysis(self, suspects: List[Tuple]) -> Dict:
        """Analyze and blame drivers for crashes"""
        suspicious_drivers = {}
        
        # Drivers commonly associated with crashes
        known_problematic = {
            'nvidiakernelmodule': {'name': 'NVIDIA GPU Driver', 'score': 0.85},
            'atikmdag': {'name': 'AMD GPU Driver', 'score': 0.80},
            'igdkmd': {'name': 'Intel GPU Driver', 'score': 0.75},
            'disk': {'name': 'Disk Controller', 'score': 0.70},
            'nvme': {'name': 'NVMe Controller', 'score': 0.65},
            'realtek': {'name': 'Realtek Audio', 'score': 0.60},
            'avast': {'name': 'Avast Antivirus', 'score': 0.70},
            'mcafee': {'name': 'McAfee Antivirus', 'score': 0.70},
        }
        
        for provider, eid, count in suspects:
            provider_lower = provider.lower()
            
            for keyword, info in known_problematic.items():
                if keyword in provider_lower:
                    suspicious_drivers[info['name']] = {
                        'provider': provider,
                        'occurrences': count,
                        'blame_score': info['score'] * min(count / 5, 1.0),
                        'recommendation': f"Update or reinstall {info['name']}"
                    }
        
        return dict(sorted(suspicious_drivers.items(), 
                          key=lambda x: x[1]['blame_score'], 
                          reverse=True))
    
    def temperature_analysis(self, system_info: Dict) -> Dict:
        """Analyze temperature and thermal issues"""
        warnings = []
        
        # Check storage reliability temp
        storage = system_info.get('storage_reliability', [])
        for device in storage:
            temp = device.get('Temperature', 0)
            if temp > 50:
                warnings.append({
                    'type': 'HIGH_TEMP',
                    'device': device.get('DeviceId', 'Unknown'),
                    'temperature': temp,
                    'severity': 'CRITICAL' if temp > 60 else 'HIGH',
                    'recommendation': 'Clean dust vents, check cooling paste'
                })
        
        return {'temperature_warnings': warnings}
    
    def detect_overclocking(self, bugchecks: List[Dict]) -> Dict:
        """Detect potential overclocking issues"""
        oc_indicators = {
            'memory_errors': 0,
            'whea_errors': 0,
            'irql_errors': 0,
        }
        
        for crash in bugchecks:
            code = crash.get('Code', '').lower()
            if '0x124' in code:  # WHEA_UNCORRECTABLE_ERROR
                oc_indicators['whea_errors'] += 1
            elif '0x0a' in code:  # IRQL_NOT_LESS_OR_EQUAL
                oc_indicators['irql_errors'] += 1
        
        has_oc_issues = sum(oc_indicators.values()) >= 3
        
        return {
            'likely_overclocking': has_oc_issues,
            'indicators': oc_indicators,
            'recommendation': 'Check BIOS settings, reset to stock clocks' if has_oc_issues else 'No overclocking detected'
        }
    
    def get_recommendations(self, analysis_summary: Dict) -> List[str]:
        """Generate recommendations based on crash analysis patterns"""
        recommendations = []
        
        bugchecks = analysis_summary.get('bugchecks', [])
        if bugchecks:
            # Check for pattern
            codes = [b.get('Code', '') for b in bugchecks]
            code_freq = Counter(codes)
            
            most_common = code_freq.most_common(1)
            if most_common:
                code = most_common[0][0]
                if '0x116' in code:
                    recommendations.append('GPU driver crash detected. Update GPU drivers or check for overheating.')
                elif '0x1e' in code:
                    recommendations.append('Kernel driver issue. Check for incompatible antivirus or old drivers.')
                elif '0x50' in code:
                    recommendations.append('Memory fault detected. Test RAM with Memory Diagnostic tool.')
                elif '0x124' in code:
                    recommendations.append('Hardware error detected. Check CPU/motherboard health and cooling.')
        
        # Check drivers
        driver_blame = analysis_summary.get('driver_blame', {})
        if driver_blame:
            top_driver = next(iter(driver_blame.items())) if driver_blame else None
            if top_driver and top_driver[1]['blame_score'] > 0.6:
                recommendations.append(f"Update {top_driver[0]}: {top_driver[1]['recommendation']}")
        
        # Check temps
        temps = analysis_summary.get('temperatures', {}).get('temperature_warnings', [])
        if temps:
            recommendations.append(f"High device temperature detected: {temps[0]['recommendation']}")
        
        # Check overclocking
        oc = analysis_summary.get('overclocking', {})
        if oc.get('likely_overclocking'):
            recommendations.append(oc['recommendation'])
        
        return recommendations if recommendations else ['No critical issues detected. Continue monitoring.']


class CustomRuleEngine:
    """Define and execute custom diagnostic rules"""
    
    def __init__(self):
        self.rules = self._init_default_rules()
    
    def _init_default_rules(self) -> List[Dict]:
        """Initialize default diagnostic rules"""
        return [
            {
                'name': 'Frequent BSOD',
                'condition': lambda analysis: len(analysis.get('bugchecks', [])) >= 3,
                'action': 'CRITICAL',
                'message': 'System experiencing frequent crashes. Immediate investigation required.'
            },
            {
                'name': 'Driver Conflict',
                'condition': lambda analysis: len(analysis.get('suspects', [])) > 5,
                'action': 'WARNING',
                'message': 'Multiple suspicious drivers detected. Check Event Viewer for details.'
            },
            {
                'name': 'Storage Issues',
                'condition': lambda analysis: any('disk' in str(s[0]).lower() for s in analysis.get('suspects', [])),
                'action': 'WARNING',
                'message': 'Storage device errors detected. Run CHKDSK immediately.'
            }
        ]
    
    def execute_rules(self, analysis: Dict) -> List[Dict]:
        """Execute all rules against analysis data"""
        results = []
        for rule in self.rules:
            try:
                if rule['condition'](analysis):
                    results.append({
                        'rule': rule['name'],
                        'action': rule['action'],
                        'message': rule['message'],
                        'triggered': True
                    })
            except Exception:
                pass
        return results
    
    def add_rule(self, name: str, condition, action: str, message: str):
        """Add a custom rule"""
        self.rule = {
            'name': name,
            'condition': condition,
            'action': action,
            'message': message
        }
        self.rules.append(self.rule)
