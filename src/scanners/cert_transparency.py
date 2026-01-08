"""
Certificate Transparency Scanner
Queries crt.sh to discover domains and subdomains containing the brand name
"""
import asyncio
import logging
from typing import List, Dict, Any, Set
from urllib.parse import urlparse
import re
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from ..core.network import NetworkClient

logger = logging.getLogger(__name__)

class CertTransparencyScanner:
    """Scanner for Certificate Transparency logs via crt.sh"""
    
    def __init__(self, brand_name: str, official_domain: str, network_client: NetworkClient):
        self.brand_name = brand_name.lower()
        self.official_domain = official_domain.lower().replace('www.', '').split('/')[0]
        self.network = network_client
        self.results: List[Dict[str, Any]] = []
    
    def _is_official_domain(self, domain: str) -> bool:
        """
        Check if domain is an official domain (should be filtered out)
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain is official, False if suspicious
        """
        domain_lower = domain.lower()
        official_lower = self.official_domain.lower()
        
        # Exact match
        if domain_lower == official_lower:
            return True
        
        # Subdomain of official domain (e.g., www.medsenior.com.br, api.medsenior.com.br)
        if domain_lower.endswith(f'.{official_lower}'):
            return True
        
        # Common official subdomains
        official_subdomains = [
            'www', 'api', 'app', 'admin', 'portal', 'cliente', 'docs',
            'mail', 'smtp', 'mx', 'ns', 'ftp', 'cdn', 'static', 'assets'
        ]
        
        for subdomain in official_subdomains:
            if domain_lower.startswith(f'{subdomain}.') and domain_lower.endswith(f'.{official_lower}'):
                return True
        
        return False
    
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((Exception,)),
        reraise=True
    )
    async def _fetch_certificates(self) -> List[Dict[str, Any]]:
        """
        Fetch certificates from crt.sh
        
        Returns:
            List of certificate records
        """
        # Query crt.sh with wildcard search
        query_url = f"https://crt.sh/?q=%.{self.brand_name}.%&output=json"
        
        logger.info(f"Querying Certificate Transparency: {query_url}")
        
        try:
            data = await self.network.fetch_json(query_url)
            
            if not data:
                logger.warning("No data returned from crt.sh")
                return []
            
            # crt.sh can return a list or a single dict
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                logger.warning(f"Unexpected data format from crt.sh: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} certificate records from crt.sh")
            return data
            
        except Exception as e:
            logger.error(f"Error fetching certificates from crt.sh: {e}")
            raise
    
    def _extract_domains_from_cert(self, cert_record: Dict[str, Any]) -> Set[str]:
        """
        Extract unique domains from a certificate record
        
        Args:
            cert_record: Certificate record from crt.sh
            
        Returns:
            Set of unique domains
        """
        domains = set()
        
        # Common name
        common_name = cert_record.get('common_name', '')
        if common_name:
            domains.add(common_name.lower())
        
        # Name value (can contain multiple domains separated by newlines)
        name_value = cert_record.get('name_value', '')
        if name_value:
            # Split by newlines and process each
            for name in name_value.split('\n'):
                name = name.strip().lower()
                if name:
                    domains.add(name)
        
        # Subject alternative names (SAN)
        # Some records have this in different fields
        for key in ['san', 'subject_alternative_names', 'dns_names']:
            if key in cert_record:
                san_value = cert_record[key]
                if isinstance(san_value, str):
                    for name in san_value.split(','):
                        name = name.strip().lower()
                        if name:
                            domains.add(name)
                elif isinstance(san_value, list):
                    for name in san_value:
                        if isinstance(name, str):
                            domains.add(name.strip().lower())
        
        return domains
    
    def _filter_suspicious_domains(self, domains: Set[str]) -> List[str]:
        """
        Filter out official domains and return only suspicious ones
        
        Args:
            domains: Set of all discovered domains
            
        Returns:
            List of suspicious domains
        """
        suspicious = []
        
        for domain in domains:
            # Skip invalid domains
            if not domain or len(domain) < 3:
                continue
            
            # Skip wildcards (we want actual domains)
            if '*' in domain:
                continue
            
            # Skip IP addresses
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                continue
            
            # Skip if it's an official domain
            if self._is_official_domain(domain):
                logger.debug(f"Filtered out official domain: {domain}")
                continue
            
            # Check if brand name appears in domain
            if self.brand_name in domain.lower():
                suspicious.append(domain)
        
        return suspicious
    
    async def scan(self) -> List[Dict[str, Any]]:
        """
        Perform Certificate Transparency scan
        
        Returns:
            List of suspicious domain findings
        """
        logger.info(f"Starting Certificate Transparency scan for '{self.brand_name}'")
        self.results = []
        
        try:
            # Fetch certificates
            cert_records = await self._fetch_certificates()
            
            # Extract all unique domains
            all_domains = set()
            for cert_record in cert_records:
                domains = self._extract_domains_from_cert(cert_record)
                all_domains.update(domains)
            
            logger.info(f"Extracted {len(all_domains)} unique domains from certificates")
            
            # Filter suspicious domains
            suspicious_domains = self._filter_suspicious_domains(all_domains)
            
            logger.info(f"Found {len(suspicious_domains)} suspicious domains (after filtering)")
            
            # Create findings
            for domain in suspicious_domains:
                finding = {
                    'type': 'cert_transparency',
                    'domain': domain,
                    'brand': self.brand_name,
                    'official_domain': self.official_domain,
                    'source': 'crt.sh',
                    'severity': 'high',
                    'description': f'Domain "{domain}" found in Certificate Transparency logs containing brand "{self.brand_name}"'
                }
                self.results.append(finding)
            
            logger.info(f"Certificate Transparency scan completed. Found {len(self.results)} suspicious domains")
            
        except Exception as e:
            logger.error(f"Error during Certificate Transparency scan: {e}")
            # Return empty results on error (don't fail the entire scan)
        
        return self.results

