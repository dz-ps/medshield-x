"""
Network module for MedShield-X
Handles HTTP requests with automatic Tor routing for .onion addresses
Resilient retry logic with tenacity
"""
import asyncio
import aiohttp
import json
import random
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
import logging
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    retry_if_result,
)

logger = logging.getLogger(__name__)

# User-Agent rotation pool
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
]

def _is_429_or_timeout(response: Optional[aiohttp.ClientResponse]) -> bool:
    """Check if response indicates rate limiting or timeout"""
    if response is None:
        return True
    return response.status == 429

class NetworkClient:
    """HTTP client with automatic Tor routing for .onion addresses and resilient retry"""
    
    def __init__(
        self,
        tor_proxy: str = "socks5h://tor-proxy:9050",
        timeout: int = 30,
        max_retries: int = 5
    ):
        self.tor_proxy = tor_proxy
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.session: Optional[aiohttp.ClientSession] = None
    
    def _is_onion(self, url: str) -> bool:
        """Check if URL is a .onion address"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or parsed.netloc
            return hostname and hostname.endswith('.onion')
        except Exception:
            return False
    
    def _get_proxy(self, url: str) -> Optional[str]:
        """Get proxy configuration for URL"""
        if self._is_onion(url):
            logger.info(f"Detected .onion address, routing through Tor: {url}")
            return self.tor_proxy
        return None
    
    def _get_random_user_agent(self) -> str:
        """Get random user agent for rotation"""
        return random.choice(USER_AGENTS)
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={
                'User-Agent': self._get_random_user_agent()
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
        reraise=True
    )
    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True
    ) -> Optional[aiohttp.ClientResponse]:
        """
        Perform GET request with automatic Tor routing for .onion addresses
        Uses tenacity for resilient retry with exponential backoff
        
        Args:
            url: Target URL
            headers: Optional custom headers
            allow_redirects: Whether to follow redirects
            
        Returns:
            Response object or None if failed
        """
        proxy = self._get_proxy(url)
        
        # Rotate user agent
        base_headers = {'User-Agent': self._get_random_user_agent()}
        if headers:
            base_headers.update(headers)
        
        try:
            async with self.session.get(
                url,
                proxy=proxy,
                headers=base_headers,
                allow_redirects=allow_redirects,
                ssl=False if self._is_onion(url) else True
            ) as response:
                # Handle 429 (Too Many Requests) with retry
                if response.status == 429:
                    retry_after = int(response.headers.get('Retry-After', '30'))
                    logger.warning(f"Rate limited (429) for {url}, waiting {retry_after}s")
                    await asyncio.sleep(retry_after)
                    raise aiohttp.ClientResponseError(
                        request_info=response.request_info,
                        history=response.history,
                        status=429
                    )
                
                # Read response content before returning
                await response.read()
                return response
                
        except aiohttp.ClientResponseError as e:
            if e.status == 429:
                raise  # Let tenacity handle retry
            logger.error(f"HTTP error {e.status} for {url}: {e}")
            return None
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Request failed for {url}: {e}, will retry...")
            raise  # Let tenacity handle retry
        except Exception as e:
            logger.error(f"Unexpected error for {url}: {e}")
            return None
    
    async def check_alive(self, url: str) -> bool:
        """
        Check if a URL is alive (returns 200 status)
        
        Args:
            url: Target URL
            
        Returns:
            True if URL is alive, False otherwise
        """
        try:
            response = await self.get(url)
            if response:
                return response.status == 200
        except Exception as e:
            logger.debug(f"Failed to check if {url} is alive: {e}")
        return False
    
    async def fetch_json(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Fetch and parse JSON from URL
        
        Args:
            url: Target URL
            
        Returns:
            Parsed JSON dict or None if failed
        """
        try:
            response = await self.get(url)
            if response and response.status == 200:
                try:
                    # Try to get content type
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    # If it's JSON, parse directly
                    if 'application/json' in content_type:
                        return await response.json()
                    
                    # Otherwise, try to parse as text first, then JSON
                    text = await response.text()
                    return json.loads(text)
                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to parse JSON from {url}: {e}")
                    return None
                except Exception as e:
                    logger.error(f"Failed to parse JSON from {url}: {e}")
                    return None
        except Exception as e:
            logger.error(f"Failed to fetch JSON from {url}: {e}")
        return None
    
    async def fetch_text(self, url: str) -> Optional[str]:
        """
        Fetch text content from URL
        
        Args:
            url: Target URL
            
        Returns:
            Text content or None if failed
        """
        try:
            response = await self.get(url)
            if response and response.status == 200:
                try:
                    return await response.text()
                except Exception as e:
                    logger.error(f"Failed to fetch text from {url}: {e}")
                    return None
        except Exception as e:
            logger.error(f"Failed to fetch text from {url}: {e}")
        return None
