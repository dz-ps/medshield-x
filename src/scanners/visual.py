"""
Visual Phishing Scanner
Uses Computer Vision to detect brand logo, colors, and text in suspicious domains
"""
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
import cv2
import numpy as np
from PIL import Image
import pytesseract
from playwright.async_api import async_playwright, Browser, Page
import re

logger = logging.getLogger(__name__)

# MedSênior brand colors (HSV ranges for better detection)
# Hue: 100-140 (green range), Saturation: 30-100, Value: 30-100
MEDSENIOR_HSV_LOWER = np.array([100, 30, 30])
MEDSENIOR_HSV_UPPER = np.array([140, 100, 100])

# Brand slogans/keywords to search for
BRAND_KEYWORDS = [
    "bem envelhecer",
    "terceira idade",
    "plano de saúde",
    "medsênior",
    "medsenior",
    "saúde sênior",
    "envelhecimento saudável"
]

class VisualPhishingScanner:
    """Scanner for visual phishing detection using CV and OCR"""
    
    def __init__(self, logo_path: str = "/app/assets/logo.png", screenshots_dir: str = "/app/reports/screenshots"):
        self.logo_path = Path(logo_path)
        self.screenshots_dir = Path(screenshots_dir)
        self.logo_template: Optional[np.ndarray] = None
        self.browser: Optional[Browser] = None
        self.playwright = None
        self._load_logo_template()
        self._ensure_screenshots_dir()
    
    def _ensure_screenshots_dir(self):
        """Ensure screenshots directory exists"""
        try:
            self.screenshots_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Screenshots directory ready: {self.screenshots_dir}")
        except Exception as e:
            logger.error(f"Error creating screenshots directory: {e}")
    
    def _load_logo_template(self):
        """Load logo template for matching"""
        try:
            if self.logo_path.exists():
                logo_img = cv2.imread(str(self.logo_path), cv2.IMREAD_COLOR)
                if logo_img is not None:
                    self.logo_template = cv2.cvtColor(logo_img, cv2.COLOR_BGR2GRAY)
                    logger.info(f"Loaded logo template from {self.logo_path}")
                else:
                    logger.warning(f"Could not load logo image from {self.logo_path}")
            else:
                logger.warning(f"Logo file not found at {self.logo_path}")
        except Exception as e:
            logger.error(f"Error loading logo template: {e}")
    
    async def _init_browser(self):
        """Initialize Playwright browser"""
        if self.browser is None:
            if self.playwright is None:
                self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
    
    async def _close_browser(self):
        """Close Playwright browser"""
        if self.browser:
            await self.browser.close()
            self.browser = None
        if self.playwright:
            await self.playwright.stop()
            self.playwright = None
    
    def _get_domain_filename(self, url: str) -> str:
        """Generate safe filename from domain"""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        # Replace invalid filename characters
        safe_name = re.sub(r'[^\w\-_\.]', '_', domain)
        return f"{safe_name}.png"
    
    async def _capture_screenshot(self, url: str, page: Optional[Page] = None, timeout: int = 30000, save: bool = True) -> Tuple[Optional[np.ndarray], Optional[str], Optional[Page]]:
        """
        Capture screenshot of webpage using Playwright and optionally save it
        
        Args:
            url: URL to capture
            page: Optional existing page object (if None, creates new)
            timeout: Timeout in milliseconds
            save: Whether to save screenshot to disk
            
        Returns:
            Tuple of (screenshot as numpy array, screenshot_path or None, page object)
        """
        screenshot_path = None
        page_created = False
        
        try:
            if page is None:
                await self._init_browser()
                page = await self.browser.new_page()
                page_created = True
            
            # Set viewport size
            await page.set_viewport_size({"width": 1920, "height": 1080})
            
            # Navigate to URL
            await page.goto(url, wait_until="networkidle", timeout=timeout)
            
            # Wait a bit for dynamic content
            await asyncio.sleep(2)
            
            # Take screenshot
            screenshot_bytes = await page.screenshot(full_page=True)
            
            # Save screenshot if requested
            if save:
                filename = self._get_domain_filename(url)
                screenshot_path = self.screenshots_dir / filename
                try:
                    screenshot_path.write_bytes(screenshot_bytes)
                    logger.info(f"Screenshot saved: {screenshot_path}")
                except Exception as e:
                    logger.error(f"Error saving screenshot: {e}")
            
            # Convert to numpy array
            img_array = np.frombuffer(screenshot_bytes, np.uint8)
            img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
            
            return img, str(screenshot_path) if screenshot_path else None, page
            
        except Exception as e:
            logger.error(f"Error capturing screenshot for {url}: {e}")
            if page_created and page:
                await page.close()
            return None, None, None
    
    async def _detect_login_form_playwright(self, page: Page) -> bool:
        """
        Detect login forms using Playwright locators (detects dynamic forms)
        
        Args:
            page: Playwright page object
            
        Returns:
            True if login form is detected
        """
        try:
            # Check for password input fields using Playwright locator
            password_count = await page.locator('input[type="password"]').count()
            
            if password_count > 0:
                # Found password field, now check for login-related attributes
                login_keywords = ['user', 'login', 'senha', 'cpf', 'email', 'username', 'usuario', 'password']
                
                # Check input fields with login-related names/ids/placeholders
                for keyword in login_keywords:
                    # Check by name attribute
                    name_count = await page.locator(f'input[name*="{keyword}" i]').count()
                    # Check by id attribute
                    id_count = await page.locator(f'input[id*="{keyword}" i]').count()
                    # Check by placeholder attribute
                    placeholder_count = await page.locator(f'input[placeholder*="{keyword}" i]').count()
                    
                    if name_count > 0 or id_count > 0 or placeholder_count > 0:
                        logger.info(f"Login form detected: password field with login attribute '{keyword}'")
                        return True
                
                # Check form elements with login-related attributes
                for keyword in login_keywords:
                    form_count = await page.locator(f'form[id*="{keyword}" i], form[name*="{keyword}" i], form[class*="{keyword}" i]').count()
                    if form_count > 0:
                        logger.info(f"Login form detected: form with login attribute '{keyword}'")
                        return True
                
                # If password field exists, it's likely a login form
                logger.info("Login form detected: password input field found")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error detecting login form with Playwright: {e}")
            return False
    
    async def _extract_html_content(self, url: str, page: Optional[Page] = None) -> Tuple[str, Optional[Page]]:
        """
        Extract HTML content from page
        
        Args:
            url: URL to extract HTML from
            page: Optional existing page object
            
        Returns:
            Tuple of (HTML content, page object)
        """
        page_created = False
        try:
            if page is None:
                await self._init_browser()
                page = await self.browser.new_page()
                page_created = True
                await page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Get HTML content
            html_content = await page.content()
            
            if page_created:
                await page.close()
                return html_content.lower(), None
            
            return html_content.lower(), page
            
        except Exception as e:
            logger.error(f"Error extracting HTML content from {url}: {e}")
            if page_created and page:
                await page.close()
            return "", None
    
    async def _extract_html_text(self, url: str, page: Optional[Page] = None) -> Tuple[str, Optional[Page]]:
        """
        Extract text content from HTML
        
        Args:
            url: URL to extract text from
            page: Optional existing page object
            
        Returns:
            Tuple of (text content, page object)
        """
        page_created = False
        try:
            if page is None:
                await self._init_browser()
                page = await self.browser.new_page()
                page_created = True
                await page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Extract text content
            text_content = await page.evaluate("""
                () => {
                    // Remove script and style elements
                    const scripts = document.querySelectorAll('script, style');
                    scripts.forEach(el => el.remove());
                    
                    // Get all text content
                    return document.body.innerText || document.body.textContent || '';
                }
            """)
            
            if page_created:
                await page.close()
                return text_content.lower(), None
            
            return text_content.lower(), page
            
        except Exception as e:
            logger.error(f"Error extracting HTML text from {url}: {e}")
            if page_created and page:
                await page.close()
            return "", None
    
    def _detect_logo(self, screenshot: np.ndarray) -> Tuple[bool, float]:
        """
        Detect logo in screenshot using feature matching (ORB)
        
        Args:
            screenshot: Screenshot image (BGR format)
            
        Returns:
            Tuple of (found, confidence_score)
        """
        if self.logo_template is None:
            return False, 0.0
        
        try:
            # Convert screenshot to grayscale
            gray_screenshot = cv2.cvtColor(screenshot, cv2.COLOR_BGR2GRAY)
            
            # Initialize ORB detector
            orb = cv2.ORB_create(nfeatures=1000)
            
            # Find keypoints and descriptors
            kp1, des1 = orb.detectAndCompute(self.logo_template, None)
            kp2, des2 = orb.detectAndCompute(gray_screenshot, None)
            
            if des1 is None or des2 is None:
                return False, 0.0
            
            # Match features
            bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
            matches = bf.match(des1, des2)
            
            # Sort matches by distance
            matches = sorted(matches, key=lambda x: x.distance)
            
            # Calculate confidence based on number of good matches
            good_matches = [m for m in matches if m.distance < 50]
            confidence = len(good_matches) / max(len(kp1), 1) * 100
            
            # Logo detected if we have enough good matches
            found = len(good_matches) >= 10 and confidence > 5.0
            
            return found, min(confidence, 100.0)
            
        except Exception as e:
            logger.error(f"Error in logo detection: {e}")
            return False, 0.0
    
    def _extract_text_ocr(self, screenshot: np.ndarray) -> str:
        """
        Extract text from screenshot using Tesseract OCR
        
        Args:
            screenshot: Screenshot image (BGR format)
            
        Returns:
            Extracted text
        """
        try:
            # Convert BGR to RGB for PIL
            rgb_image = cv2.cvtColor(screenshot, cv2.COLOR_BGR2RGB)
            pil_image = Image.fromarray(rgb_image)
            
            # Run OCR (Portuguese language)
            text = pytesseract.image_to_string(pil_image, lang='por+eng')
            return text.lower()
            
        except Exception as e:
            logger.error(f"Error in OCR extraction: {e}")
            return ""
    
    def _detect_brand_keywords(self, text: str) -> Tuple[int, List[str]]:
        """
        Detect brand keywords in text
        
        Args:
            text: Text to search in
            
        Returns:
            Tuple of (match_count, matched_keywords)
        """
        matched_keywords = []
        text_lower = text.lower()
        
        for keyword in BRAND_KEYWORDS:
            if keyword.lower() in text_lower:
                matched_keywords.append(keyword)
        
        return len(matched_keywords), matched_keywords
    
    def _analyze_colors(self, screenshot: np.ndarray) -> Tuple[bool, float]:
        """
        Analyze dominant colors to check for MedSênior branding using HSV color space
        
        Args:
            screenshot: Screenshot image (BGR format)
            
        Returns:
            Tuple of (brand_colors_found, color_match_score)
        """
        try:
            # Resize for faster processing
            small = cv2.resize(screenshot, (200, 200))
            
            # Convert BGR to HSV (much better for color detection)
            hsv = cv2.cvtColor(small, cv2.COLOR_BGR2HSV)
            
            # Create mask for MedSênior green colors (Hue 100-140)
            mask = cv2.inRange(hsv, MEDSENIOR_HSV_LOWER, MEDSENIOR_HSV_UPPER)
            
            # Count pixels matching the color range
            matching_pixels = cv2.countNonZero(mask)
            total_pixels = small.shape[0] * small.shape[1]
            
            color_match_ratio = matching_pixels / total_pixels if total_pixels > 0 else 0.0
            color_match_percentage = color_match_ratio * 100
            
            # Colors found if at least 5% of pixels match
            colors_found = color_match_percentage > 5.0
            
            return colors_found, color_match_percentage
            
        except Exception as e:
            logger.error(f"Error in color analysis: {e}")
            return False, 0.0
    
    def _calculate_phishing_score(
        self,
        logo_found: bool,
        logo_confidence: float,
        keyword_count: int,
        matched_keywords: List[str],
        colors_found: bool,
        color_score: float,
        login_form_detected: bool
    ) -> Dict[str, Any]:
        """
        Calculate phishing score based on all indicators
        NEW LOGIC: Logo detection starts at 60 points (High Risk)
        CRITICAL: Login form + (Logo OR Keywords) = 100.0 (Credential Theft)
        
        Returns:
            Dictionary with score details
        """
        score = 0
        factors = []
        
        # CRITICAL: Login form + brand indicators = 100.0 (Credential Theft)
        if login_form_detected and (logo_found or keyword_count > 0):
            score = 100.0
            factors.append("CRITICAL: Login form detected with brand indicators - Credential theft attempt!")
            return {
                "score": 100.0,
                "severity": "critical",
                "logo_detected": logo_found,
                "logo_confidence": round(logo_confidence, 2),
                "keyword_matches": keyword_count,
                "matched_keywords": matched_keywords,
                "brand_colors_detected": colors_found,
                "color_match_percentage": round(color_score, 2),
                "login_form_detected": login_form_detected,
                "factors": factors
            }
        
        # If login form detected but no brand indicators, still high risk
        if login_form_detected:
            score = 70
            factors.append("Login form detected (high risk)")
        
        # CRITICAL: If logo is found, base score starts at 60 (High Risk)
        if logo_found:
            score = max(score, 60)  # Base score for logo detection
            factors.append(f"Logo detected (confidence: {logo_confidence:.1f}%) - Base score: 60")
        
        # Add points for keywords (up to +20)
        if keyword_count > 0:
            keyword_points = min(keyword_count * 7, 20)  # Max 20 points
            score += keyword_points
            factors.append(f"Brand keywords found (+{keyword_points}): {', '.join(matched_keywords[:3])}")
        
        # Add points for colors (up to +20)
        if colors_found:
            color_points = min(color_score / 5, 20)  # Max 20 points (5% = 1 point, 100% = 20 points)
            score += color_points
            factors.append(f"Brand colors detected (+{color_points:.1f}): {color_score:.1f}% match")
        
        # NEW RULE: Logo + (Keywords OR Colors) = CRITICAL (90+)
        if logo_found and (keyword_count > 0 or colors_found):
            score = max(score, 90)  # Ensure minimum 90 for CRITICAL
            factors.append("CRITICAL: Logo + Brand indicators detected")
        
        # Cap score at 100
        score = min(score, 100)
        
        # Determine severity based on score
        if score >= 90:
            severity = "critical"
        elif score >= 70:
            severity = "high"
        elif score >= 50:
            severity = "medium"
        elif score >= 30:
            severity = "low"
        else:
            severity = "low"
        
        return {
            "score": round(score, 2),
            "severity": severity,
            "logo_detected": logo_found,
            "logo_confidence": round(logo_confidence, 2),
            "keyword_matches": keyword_count,
            "matched_keywords": matched_keywords,
            "brand_colors_detected": colors_found,
            "color_match_percentage": round(color_score, 2),
            "login_form_detected": login_form_detected,
            "factors": factors
        }
    
    async def scan_domain(self, url: str) -> Dict[str, Any]:
        """
        Perform complete visual analysis of a domain
        
        Args:
            url: Domain URL to analyze
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting visual analysis for {url}")
        
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        page = None
        try:
            await self._init_browser()
            page = await self.browser.new_page()
            
            # Set viewport size
            await page.set_viewport_size({"width": 1920, "height": 1080})
            
            # Navigate to URL
            await page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Wait a bit for dynamic content
            await asyncio.sleep(2)
            
            # Capture screenshot and save it (reuse page)
            screenshot, screenshot_path, _ = await self._capture_screenshot(url, page=page, save=True)
            if screenshot is None:
                await page.close()
                return {
                    "url": url,
                    "error": "Failed to capture screenshot",
                    "severity": "low",
                    "score": 0,
                    "screenshot_path": None
                }
            
            # Detect login form using Playwright locators (while page is open)
            login_form_detected = await self._detect_login_form_playwright(page)
            
            # Extract HTML text (reuse page)
            html_text, _ = await self._extract_html_text(url, page=page)
            
            # Close page after all operations
            await page.close()
            page = None
            
            # Perform OCR
            ocr_text = self._extract_text_ocr(screenshot)
            combined_text = f"{html_text} {ocr_text}"
            
            # Detect logo
            logo_found, logo_confidence = self._detect_logo(screenshot)
            
            # Detect brand keywords
            keyword_count, matched_keywords = self._detect_brand_keywords(combined_text)
            
            # Analyze colors
            colors_found, color_score = self._analyze_colors(screenshot)
            
            # Calculate phishing score
            score_result = self._calculate_phishing_score(
                logo_found,
                logo_confidence,
                keyword_count,
                matched_keywords,
                colors_found,
                color_score,
                login_form_detected
            )
            
            result = {
                "type": "visual_phishing",
                "url": url,
                "severity": score_result["severity"],
                "score": score_result["score"],
                "screenshot_path": screenshot_path,
                **score_result
            }
            
            logger.info(f"Visual analysis complete for {url}: Score={score_result['score']}, Severity={score_result['severity']}, LoginForm={login_form_detected}")
            return result
            
        except Exception as e:
            logger.error(f"Error in visual analysis for {url}: {e}")
            if page:
                try:
                    await page.close()
                except:
                    pass
            return {
                "url": url,
                "error": str(e),
                "severity": "low",
                "score": 0,
                "screenshot_path": None
            }
    
    async def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        Scan multiple domains concurrently using semaphore for load control
        
        Args:
            domains: List of domain URLs
            
        Returns:
            List of analysis results
        """
        # Initialize browser once for all scans
        await self._init_browser()
        
        # Semaphore to limit concurrent scans to 3
        semaphore = asyncio.Semaphore(3)
        
        async def scan_with_semaphore(domain: str) -> Dict[str, Any]:
            """Scan a single domain with semaphore control"""
            async with semaphore:
                return await self.scan_domain(domain)
        
        # Create tasks for all domains
        tasks = [scan_with_semaphore(domain) for domain in domains]
        
        # Execute all tasks concurrently (max 3 at a time)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error scanning domain {domains[i]}: {result}")
                processed_results.append({
                    "url": domains[i],
                    "error": str(result),
                    "severity": "low",
                    "score": 0,
                    "screenshot_path": None
                })
            else:
                processed_results.append(result)
        
        # Close browser after all scans are done
        await self._close_browser()
        
        return processed_results
