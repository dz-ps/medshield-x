"""
Dark Web Scanner
Searches Ahmia.fi for .onion sites and checks ransomware feeds
"""
import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import quote
import logging

from ..core.network import NetworkClient

logger = logging.getLogger(__name__)

class DarkWebScanner:
    """Scanner for Dark Web using Ahmia.fi and Ransomware feeds"""
    
    def __init__(self, brand_name: str, network_client: NetworkClient):
        self.brand_name = brand_name.lower()
        self.network = network_client
        self.results: List[Dict[str, Any]] = []
    
    async def scan_ahmia(self) -> List[Dict[str, Any]]:
        """
        Search Ahmia.fi for brand mentions in .onion sites
        
        Returns:
            List of findings from Ahmia search
        """
        logger.info(f"Starting Ahmia.fi scan for '{self.brand_name}'")
        ahmia_results = []
        
        # Ahmia.fi search URL (clearweb mirror)
        search_url = f"https://ahmia.fi/search/?q={quote(self.brand_name)}"
        
        try:
            html = await self.network.fetch_text(search_url)
            if not html:
                logger.warning("Failed to fetch Ahmia.fi search results")
                return ahmia_results
            
            # Extract .onion links from HTML
            onion_pattern = r'([a-z2-7]{16,56}\.onion)'
            onion_links = re.findall(onion_pattern, html, re.IGNORECASE)
            
            # Also try to extract from search results structure
            # Ahmia typically shows results with .onion addresses
            result_pattern = r'href="(https?://[a-z2-7]{16,56}\.onion[^"]*)"'
            result_links = re.findall(result_pattern, html, re.IGNORECASE)
            
            all_onion_urls = set()
            
            # Add full URLs
            for url in result_links:
                all_onion_urls.add(url)
            
            # Construct URLs from onion addresses
            for onion in onion_links:
                all_onion_urls.add(f"http://{onion}")
            
            logger.info(f"Found {len(all_onion_urls)} potential .onion addresses")
            
            # Check if each .onion site is alive
            for onion_url in all_onion_urls:
                try:
                    logger.info(f"Checking if .onion site is alive: {onion_url}")
                    is_alive = await self.network.check_alive(onion_url)
                    
                    finding = {
                        'type': 'dark_web',
                        'source': 'ahmia',
                        'url': onion_url,
                        'onion_address': onion_url.split('//')[1].split('/')[0] if '//' in onion_url else onion_url,
                        'alive': is_alive,
                        'brand_mention': self.brand_name,
                        'severity': 'high' if is_alive else 'medium'
                    }
                    ahmia_results.append(finding)
                    
                    # Delay between checks
                    await asyncio.sleep(3)
                    
                except Exception as e:
                    logger.error(f"Error checking .onion site {onion_url}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Error during Ahmia scan: {e}")
        
        logger.info(f"Ahmia scan completed. Found {len(ahmia_results)} results")
        return ahmia_results
    
    async def scan_ransomware_feeds(self) -> List[Dict[str, Any]]:
        """
        Check ransomware victim feeds for brand mentions
        
        Returns:
            List of findings from ransomware feeds
        """
        logger.info(f"Starting Ransomware Feed scan for '{self.brand_name}'")
        ransomware_results = []
        
        # Ransomwatch GitHub feed
        feed_url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
        
        try:
            # Try to fetch as JSON first
            data = await self.network.fetch_json(feed_url)
            
            # If JSON parsing failed, try to parse as text/JSON
            if not data:
                text_data = await self.network.fetch_text(feed_url)
                if text_data:
                    try:
                        import json
                        data = json.loads(text_data)
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse ransomware feed as JSON")
                        return ransomware_results
                else:
                    logger.warning("Failed to fetch ransomware feed")
                    return ransomware_results
            
            if not data:
                logger.warning("Failed to fetch ransomware feed")
                return ransomware_results
            
            # Search for brand name in the feed
            brand_lower = self.brand_name.lower()
            
            for entry in data:
                # Check various fields for brand mention
                post_title = str(entry.get('post_title', '')).lower()
                group_name = str(entry.get('group_name', '')).lower()
                discovered = str(entry.get('discovered', '')).lower()
                url = str(entry.get('url', '')).lower()
                
                if brand_lower in post_title or brand_lower in url:
                    finding = {
                        'type': 'ransomware',
                        'source': 'ransomwatch',
                        'group_name': entry.get('group_name', 'N/A'),
                        'post_title': entry.get('post_title', 'N/A'),
                        'url': entry.get('url', 'N/A'),
                        'discovered': entry.get('discovered', 'N/A'),
                        'published': entry.get('published', 'N/A'),
                        'brand_mention': self.brand_name,
                        'severity': 'critical'
                    }
                    ransomware_results.append(finding)
                    logger.warning(f"CRITICAL: Brand found in ransomware feed! Group: {entry.get('group_name')}")
            
        except Exception as e:
            logger.error(f"Error during ransomware feed scan: {e}")
        
        logger.info(f"Ransomware feed scan completed. Found {len(ransomware_results)} results")
        return ransomware_results
    
    async def scan(self) -> List[Dict[str, Any]]:
        """
        Perform complete dark web scan
        
        Returns:
            Combined list of findings from all dark web sources
        """
        self.results = []
        
        # Run scans concurrently
        ahmia_results, ransomware_results = await asyncio.gather(
            self.scan_ahmia(),
            self.scan_ransomware_feeds(),
            return_exceptions=True
        )
        
        if isinstance(ahmia_results, list):
            self.results.extend(ahmia_results)
        else:
            logger.error(f"Ahmia scan failed: {ahmia_results}")
        
        if isinstance(ransomware_results, list):
            self.results.extend(ransomware_results)
        else:
            logger.error(f"Ransomware scan failed: {ransomware_results}")
        
        return self.results

