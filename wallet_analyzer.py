#!/usr/bin/env python3
"""
Crypto Wallet Security Analyzer
Analyzes cryptocurrency wallet security practices and provides recommendations.
"""

import re
import hashlib
import secrets
from typing import List, Dict, Tuple


class WalletSecurityAnalyzer:
    """Analyzes wallet security based on best practices."""
    
    def __init__(self):
        self.security_score = 0
        self.vulnerabilities = []
        self.recommendations = []
    
    def analyze_password_strength(self, password: str) -> Dict[str, any]:
        """Analyze password strength for wallet protection."""
        score = 0
        issues = []
        
        # Length check
        if len(password) < 12:
            issues.append("Password too short (minimum 12 characters)")
        else:
            score += 25
        
        # Complexity checks
        if re.search(r'[a-z]', password):
            score += 15
        else:
            issues.append("No lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 15
        else:
            issues.append("No uppercase letters")
        
        if re.search(r'\d', password):
            score += 15
        else:
            issues.append("No numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 15
        else:
            issues.append("No special characters")
        
        # Common patterns check
        common_patterns = ['123', 'abc', 'qwerty', 'password']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 20
            issues.append("Contains common patterns")
        
        # Length bonus
        if len(password) >= 16:
            score += 15
        
        return {
            'score': max(0, min(100, score)),
            'strength': self._get_strength_label(score),
            'issues': issues
        }
    
    def _get_strength_label(self, score: int) -> str:
        """Convert score to strength label."""
        if score >= 80:
            return "Strong"
        elif score >= 60:
            return "Moderate"
        elif score >= 40:
            return "Weak"
        else:
            return "Very Weak"
    
    def check_seed_phrase_security(self, seed_phrase: str) -> Dict[str, any]:
        """Check security of seed phrase storage and format."""
        words = seed_phrase.strip().split()
        issues = []
        score = 100
        
        # Standard BIP39 lengths: 12, 15, 18, 21, 24 words
        valid_lengths = [12, 15, 18, 21, 24]
        if len(words) not in valid_lengths:
            issues.append(f"Invalid seed phrase length: {len(words)} words")
            score -= 30
        
        # Check for duplicates
        if len(words) != len(set(words)):
            issues.append("Seed phrase contains duplicate words")
            score -= 20
        
        # Check for numeric-only words (potential weakness)
        if any(word.isdigit() for word in words):
            issues.append("Seed phrase contains numeric-only words")
            score -= 10
        
        return {
            'score': max(0, score),
            'word_count': len(words),
            'is_valid_length': len(words) in valid_lengths,
            'issues': issues
        }
    
    def generate_secure_backup_checksum(self, data: str) -> str:
        """Generate SHA-256 checksum for backup verification."""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def assess_two_factor_auth(self, has_2fa: bool, method: str = None) -> Dict[str, any]:
        """Assess 2FA implementation."""
        score = 0
        recommendations = []
        
        if not has_2fa:
            recommendations.append("Enable Two-Factor Authentication immediately")
            recommendations.append("Use hardware security keys (YubiKey, Ledger)")
            return {
                'score': 0,
                'enabled': False,
                'recommendations': recommendations
            }
        
        score = 50  # Base score for having 2FA
        
        if method:
            method = method.lower()
            if 'hardware' in method or 'yubikey' in method:
                score += 50
                recommendations.append("Excellent: Hardware 2FA is most secure")
            elif 'authenticator' in method or 'totp' in method:
                score += 35
                recommendations.append("Good: Consider upgrading to hardware key")
            elif 'sms' in method:
                score += 15
                recommendations.append("Warning: SMS 2FA is vulnerable to SIM swapping")
                recommendations.append("Upgrade to authenticator app or hardware key")
        
        return {
            'score': score,
            'enabled': True,
            'method': method,
            'recommendations': recommendations
        }
    
    def check_wallet_address_format(self, address: str, blockchain: str = 'ethereum') -> bool:
        """Basic validation of wallet address format."""
        patterns = {
            'ethereum': r'^0x[a-fA-F0-9]{40}$',
            'bitcoin': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$',
            'solana': r'^[1-9A-HJ-NP-Za-km-z]{32,44}$'
        }
        
        if blockchain.lower() not in patterns:
            return False
        
        return bool(re.match(patterns[blockchain.lower()], address))
    
    def generate_security_report(self, 
                                password: str,
                                seed_phrase: str = None,
                                has_2fa: bool = False,
                                tfa_method: str = None) -> Dict:
        """Generate comprehensive security report."""
        report = {
            'timestamp': 'Security Analysis Report',
            'overall_score': 0,
            'components': {}
        }
        
        # Password analysis
        password_result = self.analyze_password_strength(password)
        report['components']['password'] = password_result
        
        # Seed phrase analysis
        if seed_phrase:
            seed_result = self.check_seed_phrase_security(seed_phrase)
            report['components']['seed_phrase'] = seed_result
        
        # 2FA analysis
        tfa_result = self.assess_two_factor_auth(has_2fa, tfa_method)
        report['components']['two_factor_auth'] = tfa_result
        
        # Calculate overall score
        scores = []
        if 'password' in report['components']:
            scores.append(report['components']['password']['score'])
        if 'seed_phrase' in report['components']:
            scores.append(report['components']['seed_phrase']['score'])
        if 'two_factor_auth' in report['components']:
            scores.append(report['components']['two_factor_auth']['score'])
        
        report['overall_score'] = sum(scores) / len(scores) if scores else 0
        
        # Critical recommendations
        report['critical_recommendations'] = self._generate_recommendations(report)
        
        return report
    
    def _generate_recommendations(self, report: Dict) -> List[str]:
        """Generate prioritized recommendations based on analysis."""
        recommendations = []
        
        if report['overall_score'] < 50:
            recommendations.append("\u26a0 CRITICAL: Your wallet security is at high risk!")
        
        password_score = report['components'].get('password', {}).get('score', 0)
        if password_score < 60:
            recommendations.append("Use a password manager to generate strong passwords")
        
        if not report['components'].get('two_factor_auth', {}).get('enabled', False):
            recommendations.append("Enable 2FA immediately - this is your most critical security gap")
        
        if 'seed_phrase' in report['components']:
            if report['components']['seed_phrase']['score'] < 80:
                recommendations.append("Review and secure your seed phrase backup")
        
        recommendations.extend([
            "Never share your private keys or seed phrase",
            "Use hardware wallets for large holdings",
            "Keep wallet software updated",
            "Verify addresses before transactions",
            "Use multiple wallets for diversification"
        ])
        
        return recommendations
    
    def print_report(self, report: Dict):
        """Print formatted security report."""
        print("=" * 60)
        print("     CRYPTO WALLET SECURITY ANALYSIS REPORT")
        print("=" * 60)
        print(f"\nOverall Security Score: {report['overall_score']:.1f}/100")
        print(f"Security Level: {self._get_security_level(report['overall_score'])}")
        
        print("\n" + "-" * 60)
        print("COMPONENT ANALYSIS:")
        print("-" * 60)
        
        for component, data in report['components'].items():
            print(f"\n{component.replace('_', ' ').title()}:")
            print(f"  Score: {data.get('score', 'N/A')}/100")
            
            if 'strength' in data:
                print(f"  Strength: {data['strength']}")
            
            if 'issues' in data and data['issues']:
                print("  Issues:")
                for issue in data['issues']:
                    print(f"    - {issue}")
            
            if 'recommendations' in data and data['recommendations']:
                print("  Recommendations:")
                for rec in data['recommendations']:
                    print(f"    - {rec}")
        
        print("\n" + "-" * 60)
        print("CRITICAL RECOMMENDATIONS:")
        print("-" * 60)
        for i, rec in enumerate(report['critical_recommendations'], 1):
            print(f"{i}. {rec}")
        print("=" * 60)
    
    def _get_security_level(self, score: float) -> str:
        """Get security level description."""
        if score >= 80:
            return "✅ Excellent"
        elif score >= 60:
            return "⚠ Good (Improvements needed)"
        elif score >= 40:
            return "⚠ Fair (Significant risks)"
        else:
            return "❌ Critical (Immediate action required)"


if __name__ == "__main__":
    # Demo usage
    analyzer = WalletSecurityAnalyzer()
    
    print("Crypto Wallet Security Analyzer Demo\n")
    
    # Example 1: Weak security
    print("Example 1: Analyzing weak security setup...")
    report1 = analyzer.generate_security_report(
        password="password123",
        seed_phrase="word word word word word word word word word word word word",
        has_2fa=False
    )
    analyzer.print_report(report1)
    
    print("\n" + "#" * 60 + "\n")
    
    # Example 2: Strong security
    print("Example 2: Analyzing strong security setup...")
    report2 = analyzer.generate_security_report(
        password="MyS3cur3P@ssw0rd!2025#Crypto",
        seed_phrase="abandon ability able about above absent absorb abstract absurd abuse access accident",
        has_2fa=True,
        tfa_method="hardware"
    )
    analyzer.print_report(report2)
