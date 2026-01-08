"""
AI Analysis Engine
Uses local Ollama instance for intelligent threat analysis
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
import aiohttp
import json

logger = logging.getLogger(__name__)

class AIAnalyst:
    """AI-powered threat analyst using Ollama"""
    
    def __init__(self, ollama_url: str = "http://host.docker.internal:11434/api/generate", model: str = "llama3"):
        self.ollama_url = ollama_url
        self.model = model
        self.timeout = aiohttp.ClientTimeout(total=60)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _check_ollama_available(self) -> bool:
        """Check if Ollama is available"""
        try:
            async with self.session.get(f"{self.ollama_url.rsplit('/api/generate', 1)[0]}/api/tags") as response:
                return response.status == 200
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            return False
    
    async def _generate(self, prompt: str) -> Optional[str]:
        """
        Generate response from Ollama
        
        Args:
            prompt: Prompt to send to Ollama
            
        Returns:
            Generated response or None if failed
        """
        if not self.session:
            return None
        
        try:
            # Check if Ollama is available
            if not await self._check_ollama_available():
                logger.warning("Ollama is not available, skipping AI analysis")
                return None
            
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                }
            }
            
            async with self.session.post(
                self.ollama_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get('response', '').strip()
                else:
                    logger.error(f"Ollama API returned status {response.status}")
                    return None
                    
        except aiohttp.ClientError as e:
            logger.error(f"Error connecting to Ollama: {e}")
            return None
        except Exception as e:
            logger.error(f"Error generating AI response: {e}")
            return None
    
    async def analyze_finding(self, text_content: str, brand: str, url: str = "") -> Dict[str, Any]:
        """
        Analyze a finding to determine if it's a phishing attempt
        
        Args:
            text_content: Text content from the website
            brand: Brand name being targeted
            url: URL of the website (optional)
            
        Returns:
            Dictionary with analysis results
        """
        if not text_content or len(text_content.strip()) < 50:
            return {
                "is_phishing": False,
                "confidence": "low",
                "reasoning": "Insufficient content for analysis",
                "available": False
            }
        
        # Truncate content if too long (Ollama has token limits)
        content_preview = text_content[:2000] if len(text_content) > 2000 else text_content
        
        prompt = f"""Analyze this text content from a website. Does it look like a phishing attempt targeting the brand "{brand}"?

Website URL: {url if url else "Not provided"}
Text Content:
{content_preview}

Answer in the following format:
VERDICT: YES or NO
CONFIDENCE: HIGH, MEDIUM, or LOW
REASONING: [Brief explanation of why this is or isn't phishing]

Focus on:
- Suspicious language or urgency
- Requests for credentials or personal information
- Brand impersonation attempts
- Unusual domain names or URLs
- Grammatical errors or inconsistencies"""
        
        try:
            response = await self._generate(prompt)
            
            if not response:
                return {
                    "is_phishing": False,
                    "confidence": "unknown",
                    "reasoning": "AI Analysis Unavailable - Ollama service not accessible",
                    "available": False
                }
            
            # Parse response
            is_phishing = False
            confidence = "unknown"
            reasoning = response
            
            # Try to extract structured information
            if "VERDICT: YES" in response.upper() or "YES" in response.upper()[:50]:
                is_phishing = True
            
            if "CONFIDENCE: HIGH" in response.upper():
                confidence = "high"
            elif "CONFIDENCE: MEDIUM" in response.upper():
                confidence = "medium"
            elif "CONFIDENCE: LOW" in response.upper():
                confidence = "low"
            
            # Extract reasoning if present
            if "REASONING:" in response.upper():
                reasoning_parts = response.upper().split("REASONING:")
                if len(reasoning_parts) > 1:
                    reasoning = reasoning_parts[1].strip()
            
            return {
                "is_phishing": is_phishing,
                "confidence": confidence,
                "reasoning": reasoning,
                "available": True,
                "raw_response": response
            }
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {e}")
            return {
                "is_phishing": False,
                "confidence": "unknown",
                "reasoning": f"AI Analysis Error: {str(e)}",
                "available": False
            }
    
    async def generate_summary(self, total_findings: int, critical_count: int, high_count: int, brand: str) -> str:
        """
        Generate executive summary of the scan results
        
        Args:
            total_findings: Total number of findings
            critical_count: Number of critical findings
            high_count: Number of high severity findings
            brand: Brand name being monitored
            
        Returns:
            Executive summary text
        """
        prompt = f"""Generate a professional, concise executive summary for a brand protection security scan.

Brand: {brand}
Total Findings: {total_findings}
Critical Severity: {critical_count}
High Severity: {high_count}

Write a brief paragraph (2-3 sentences) summarizing the threat landscape for this brand. Focus on:
- Overall risk level
- Most significant threats identified
- Recommended actions

Keep it professional and suitable for executive reporting."""
        
        try:
            response = await self._generate(prompt)
            
            if not response:
                return f"AI Analysis Unavailable - Ollama service not accessible. Manual review recommended for {total_findings} findings ({critical_count} critical, {high_count} high severity)."
            
            return response.strip()
            
        except Exception as e:
            logger.error(f"Error generating AI summary: {e}")
            return f"AI Summary Generation Failed: {str(e)}. Manual review recommended for {total_findings} findings ({critical_count} critical, {high_count} high severity)."

