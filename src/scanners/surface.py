"""
Surface Web Scanner
Uses DuckDuckGo to search for brand leaks in paste sites and public repositories
"""
import asyncio
import random
import re
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor
import logging

# Try new package first, fallback to old one
try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        raise ImportError("Please install 'ddgs' package: pip install ddgs")

logger = logging.getLogger(__name__)

class SurfaceWebScanner:
    """Scanner for Surface Web using DuckDuckGo dorking"""
    
    def __init__(self, brand_name: str, delay_range: tuple = (5, 12)):
        self.brand_name = brand_name.lower()
        self.delay_range = delay_range
        self.results: List[Dict[str, Any]] = []
        self.executor = ThreadPoolExecutor(max_workers=2)
    
    def _generate_dork_queries(self) -> List[str]:
        """Generate dork queries for brand monitoring"""
        queries = [
            f'site:pastebin.com "{self.brand_name}"',
            f'site:trello.com "{self.brand_name}"',
            f'site:github.com "{self.brand_name}"',
            f'site:gitlab.com "{self.brand_name}"',
            f'site:bitbucket.org "{self.brand_name}"',
            f'"{self.brand_name}" filetype:env',
            f'"{self.brand_name}" filetype:config',
            f'"{self.brand_name}" filetype:key',
            f'"{self.brand_name}" filetype:sql',
            f'"{self.brand_name}" filetype:log',
            f'site:hastebin.com "{self.brand_name}"',
            f'site:justpaste.it "{self.brand_name}"',
            f'site:dpaste.com "{self.brand_name}"',
            f'"{self.brand_name}" "password"',
            f'"{self.brand_name}" "api key"',
            f'"{self.brand_name}" "secret"',
        ]
        return queries
    
    def _search_sync(self, query: str, max_retries: int = 2) -> List[Dict[str, Any]]:
        """Synchronous search wrapper for DuckDuckGo with retry logic"""
        for attempt in range(max_retries):
            try:
                ddgs = DDGS(timeout=20)  # 20 second timeout
                results = list(ddgs.text(query, max_results=10))
                return results
            except Exception as e:
                error_msg = str(e).lower()
                # Check for 429 or timeout
                is_429 = '429' in error_msg or 'too many requests' in error_msg
                is_timeout = 'timeout' in error_msg or 'timed out' in error_msg
                
                if is_429 or is_timeout:
                    if attempt < max_retries - 1:
                        logger.warning(f"Rate limit/timeout for query '{query}', retrying ({attempt + 1}/{max_retries})...")
                        # Wait 30 seconds before retry
                        import time
                        time.sleep(30)
                        continue
                    else:
                        logger.error(f"Rate limit/timeout after {max_retries} attempts for query '{query}'")
                else:
                    logger.error(f"Error in sync search for '{query}': {e}")
                return []
        return []
    
    async def scan(self) -> List[Dict[str, Any]]:
        """
        Perform surface web scan using DuckDuckGo
        
        Returns:
            List of findings with title, url, and snippet
        """
        logger.info(f"Starting Surface Web scan for '{self.brand_name}'")
        self.results = []
        
        queries = self._generate_dork_queries()
        total_queries = len(queries)
        
        for idx, query in enumerate(queries, 1):
            try:
                logger.info(f"Searching [{idx}/{total_queries}]: {query}")
                
                # Run DuckDuckGo search in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                results = await loop.run_in_executor(
                    self.executor,
                    self._search_sync,
                    query
                )
                
                # Check if we got rate limited or timeout (empty results might indicate this)
                if not results:
                    error_msg = f"Query '{query}' returned no results (possibly rate limited)"
                    logger.warning(error_msg)
                    # Wait 30 seconds before next query if we suspect rate limiting
                    logger.info("Waiting 30 seconds before next query to avoid rate limiting...")
                    await asyncio.sleep(30)
                    continue
                
                # Filter and validate results
                valid_results = []
                for result in results:
                    # Validate that result actually contains brand name
                    if not self._is_valid_result(result):
                        logger.debug(f"Filtered out result (no brand mention): {result.get('title', 'N/A')[:50]}")
                        continue
                    
                    # Filter out irrelevant results (official sites, etc.)
                    if not self._is_relevant_result(result):
                        logger.debug(f"Filtered out result (irrelevant): {result.get('title', 'N/A')[:50]}")
                        continue
                    
                    valid_results.append(result)
                
                # Add validated results
                for result in valid_results:
                    finding = {
                        'type': 'surface_web',
                        'query': query,
                        'title': result.get('title', 'N/A'),
                        'url': result.get('href', 'N/A'),
                        'snippet': result.get('body', 'N/A'),
                        'source': 'duckduckgo',
                        'severity': self._assess_severity(result)
                    }
                    self.results.append(finding)
                
                logger.info(f"Found {len(valid_results)} valid results (from {len(results)} total) for query {idx}/{total_queries}")
                
                # Random delay between queries (increased for stability)
                if idx < total_queries:  # Don't delay after last query
                    delay = random.uniform(*self.delay_range)
                    await asyncio.sleep(delay)
                
            except Exception as e:
                error_msg = str(e).lower()
                # Check if it's a 429 or timeout
                is_429 = '429' in error_msg or 'too many requests' in error_msg
                is_timeout = 'timeout' in error_msg or 'timed out' in error_msg
                
                if is_429 or is_timeout:
                    logger.error(f"Rate limit/timeout for query '{query}': {e}")
                    logger.info("Waiting 30 seconds before next query...")
                    await asyncio.sleep(30)
                else:
                    logger.error(f"Error searching query '{query}': {e}")
                continue
        
        self.executor.shutdown(wait=False)
        logger.info(f"Surface Web scan completed. Found {len(self.results)} total results")
        return self.results
    
    def _is_valid_result(self, result: Dict[str, Any]) -> bool:
        """
        Validate if result actually contains the brand name
        
        Returns:
            True if result is valid (contains brand mention), False otherwise
        """
        title = result.get('title', '').lower()
        body = result.get('body', '').lower()
        url = result.get('href', '').lower()
        
        # Check if brand name appears in title, body, or URL
        content = f"{title} {body} {url}"
        
        # Exact match or word boundary match
        brand_lower = self.brand_name.lower()
        
        # Check for exact brand name (with word boundaries)
        pattern = r'\b' + re.escape(brand_lower) + r'\b'
        if re.search(pattern, content):
            return True
        
        # Also check for common variations (without word boundaries for compound words)
        if brand_lower in content:
            # But exclude if it's just part of a larger word (unless it's the main word)
            # This helps catch "medsenior" in "medsenior.com" but not "medseniority"
            if brand_lower in title or brand_lower in body:
                return True
            if brand_lower in url and ('.' in url or '/' in url):  # Domain or path
                return True
        
        return False
    
    def _is_relevant_result(self, result: Dict[str, Any]) -> bool:
        """
        Filter out irrelevant results (official sites, generic pages)
        
        Returns:
            True if result is relevant, False if it should be filtered out
        """
        url = result.get('href', '').lower()
        title = result.get('title', '').lower()
        
        # Filter out official domains (these are expected, not leaks)
        official_domains = [
            'medsenior.com.br',
            'medsenior.com',
            'medseniorbrasil.com.br',
            'cliente.medsenior',
            'portaldocliente.medsenior',
            'guiamedico.medsenior',
            'docs.medsenior',
            'vendadigital.medsenior',
            'pmp.medsenior',
            'medilab.medsenior',
            'planium.io',  # Official platform
        ]
        
        # Skip official domains unless they contain sensitive keywords
        for domain in official_domains:
            if domain in url:
                # Only include if it has sensitive keywords
                sensitive_keywords = ['password', 'api', 'key', 'secret', 'token', 'credential', 'login', 'env', 'config']
                content = f"{title} {url}".lower()
                if not any(kw in content for kw in sensitive_keywords):
                    return False
        
        # Filter out generic pages (LinkedIn, Facebook, etc.) unless they have sensitive content
        generic_sites = ['linkedin.com', 'facebook.com', 'twitter.com', 'instagram.com']
        for site in generic_sites:
            if site in url:
                sensitive_keywords = ['password', 'api', 'key', 'secret', 'token', 'credential', 'leak', 'breach', 'hack']
                content = f"{title} {result.get('body', '')}".lower()
                if not any(kw in content for kw in sensitive_keywords):
                    return False
        
        return True
    
    def _assess_severity(self, result: Dict[str, Any]) -> str:
        """Assess severity based on content type and keywords"""
        title = result.get('title', '').lower()
        body = result.get('body', '').lower()
        url = result.get('href', '').lower()
        
        high_risk_keywords = ['password', 'api key', 'secret', 'token', 'credential', 'env', 'config', 'leak', 'breach']
        medium_risk_keywords = ['login', 'admin', 'database', 'sql', 'key']
        
        content = f"{title} {body} {url}"
        
        # Check for paste sites - these are higher risk
        paste_sites = ['pastebin.com', 'hastebin.com', 'justpaste.it', 'dpaste.com']
        is_paste_site = any(site in url for site in paste_sites)
        
        if any(keyword in content for keyword in high_risk_keywords):
            return 'high' if is_paste_site else 'medium'
        elif any(keyword in content for keyword in medium_risk_keywords):
            return 'medium' if is_paste_site else 'low'
        else:
            return 'low' if is_paste_site else 'low'
