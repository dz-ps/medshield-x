"""
DNS/Typosquatting Scanner
Checks for phishing domains using dnstwist-like logic
"""
import asyncio
import dns.resolver
from typing import List, Dict, Any, Set
import logging
import string

logger = logging.getLogger(__name__)

class DNSScanner:
    """Scanner for DNS typosquatting and phishing domains"""
    
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        self.base_domain = self.domain.replace('www.', '').split('/')[0]
        self.results: List[Dict[str, Any]] = []
    
    def _generate_variations(self) -> Set[str]:
        """
        Generate domain variations similar to dnstwist
        
        Returns:
            Set of potential typosquatting domains
        """
        variations = set()
        domain_parts = self.base_domain.split('.')
        
        if len(domain_parts) < 2:
            return variations
        
        name = domain_parts[0]
        tld = '.'.join(domain_parts[1:])
        
        # Common typosquatting techniques
        variations.add(f"{name}-login.{tld}")
        variations.add(f"{name}-secure.{tld}")
        variations.add(f"{name}-portal.{tld}")
        variations.add(f"{name}-auth.{tld}")
        variations.add(f"login-{name}.{tld}")
        variations.add(f"secure-{name}.{tld}")
        variations.add(f"www-{name}.{tld}")
        variations.add(f"{name}-www.{tld}")
        
        # Character substitution (common typos)
        char_map = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', 'l'],
            'o': ['0'],
            's': ['5', '$'],
            'l': ['1', 'i'],
            'g': ['9'],
        }
        
        for char, replacements in char_map.items():
            if char in name:
                for replacement in replacements:
                    new_name = name.replace(char, replacement, 1)
                    variations.add(f"{new_name}.{tld}")
        
        # Omission (missing characters)
        if len(name) > 3:
            for i in range(len(name)):
                if i < len(name) - 1:
                    new_name = name[:i] + name[i+1:]
                    variations.add(f"{new_name}.{tld}")
        
        # Insertion (extra characters) - limited to most common
        for char in ['1', '2', '0', 'a', 'e', 'i', 'o']:  # Common typos
            for i in range(min(len(name), 5)):  # Limit positions
                new_name = name[:i] + char + name[i:]
                variations.add(f"{new_name}.{tld}")
        
        # Transposition (swapped adjacent characters)
        for i in range(len(name) - 1):
            chars = list(name)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            new_name = ''.join(chars)
            variations.add(f"{new_name}.{tld}")
        
        # TLD variations
        common_tlds = ['com', 'net', 'org', 'co', 'io', 'info']
        if tld not in common_tlds:
            for alt_tld in common_tlds:
                variations.add(f"{name}.{alt_tld}")
        
        return variations
    
    async def _check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check if a domain exists and resolve its IP
        
        Args:
            domain: Domain to check
            
        Returns:
            Domain information dict
        """
        try:
            # Try to resolve A record
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # Try to get MX record
            mx_records = []
            try:
                mx_answers = resolver.resolve(domain, 'MX')
                mx_records = [str(rdata) for rdata in mx_answers]
            except:
                pass
            
            return {
                'domain': domain,
                'exists': True,
                'ips': ips,
                'mx_records': mx_records,
                'threat_level': 'high' if ips else 'medium'
            }
            
        except dns.resolver.NXDOMAIN:
            return {
                'domain': domain,
                'exists': False,
                'ips': [],
                'mx_records': [],
                'threat_level': 'none'
            }
        except dns.resolver.NoAnswer:
            return {
                'domain': domain,
                'exists': True,
                'ips': [],
                'mx_records': [],
                'threat_level': 'medium'
            }
        except Exception as e:
            logger.debug(f"DNS check failed for {domain}: {e}")
            return {
                'domain': domain,
                'exists': False,
                'ips': [],
                'mx_records': [],
                'threat_level': 'none',
                'error': str(e)
            }
    
    async def scan(self) -> List[Dict[str, Any]]:
        """
        Perform DNS typosquatting scan
        
        Returns:
            List of suspicious domains found
        """
        logger.info(f"Starting DNS typosquatting scan for '{self.base_domain}'")
        self.results = []
        
        variations = self._generate_variations()
        logger.info(f"Generated {len(variations)} domain variations")
        
        # Check ALL variations (no limit)
        variations_list = list(variations)
        logger.info(f"Checking {len(variations_list)} domain variations")
        
        tasks = []
        batch_size = 50  # Increased batch size for faster processing (DNS queries are lightweight)
        for variation in variations_list:
            tasks.append(self._check_domain(variation))
            # Process in batches
            if len(tasks) >= batch_size:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, dict) and result.get('exists'):
                        finding = {
                            'type': 'dns_typosquatting',
                            'suspicious_domain': result['domain'],
                            'original_domain': self.base_domain,
                            'ips': result['ips'],
                            'mx_records': result['mx_records'],
                            'threat_level': result['threat_level'],
                            'severity': 'high' if result['threat_level'] == 'high' else 'medium'
                        }
                        self.results.append(finding)
                tasks = []
                await asyncio.sleep(0.2)  # Small delay between batches
        
        # Process remaining tasks
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, dict) and result.get('exists'):
                    finding = {
                        'type': 'dns_typosquatting',
                        'suspicious_domain': result['domain'],
                        'original_domain': self.base_domain,
                        'ips': result['ips'],
                        'mx_records': result['mx_records'],
                        'threat_level': result['threat_level'],
                        'severity': 'high' if result['threat_level'] == 'high' else 'medium'
                    }
                    self.results.append(finding)
        
        logger.info(f"DNS scan completed. Found {len(self.results)} suspicious domains")
        return self.results
