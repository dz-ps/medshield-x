"""
HTML Reporter for MedShield-X
Generates professional CTI dashboard with visual evidence (Base64 embedded)
"""
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import logging
import base64

logger = logging.getLogger(__name__)

def generate_html_report(results: List[Dict[str, Any]], output_path: str, brand: str):
    """
    Generate HTML CTI dashboard report with Base64 embedded screenshots
    
    Args:
        results: List of scan results
        output_path: Path to save HTML report
        brand: Brand name being monitored
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Group results by type
    by_type = {}
    for result in results:
        result_type = result.get('type', 'unknown')
        if result_type not in by_type:
            by_type[result_type] = []
        by_type[result_type].append(result)
    
    # Count severities
    severity_counts = {}
    for result in results:
        severity = result.get('severity', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Generate HTML
    html_content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MedShield-X CTI Report - {brand}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        
        .header {{
            border-bottom: 3px solid #2563eb;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            color: #2563eb;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .meta {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .stat-card.critical {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        
        .stat-card.high {{
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }}
        
        .stat-card.medium {{
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }}
        
        .stat-card.low {{
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }}
        
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 0.9em;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section-title {{
            font-size: 1.8em;
            color: #2563eb;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e5e7eb;
        }}
        
        .finding-card {{
            background: #f9fafb;
            border-left: 4px solid #e5e7eb;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 4px;
            transition: all 0.3s ease;
        }}
        
        .finding-card:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }}
        
        .finding-card.critical {{
            border-left-color: #ef4444;
            background: #fef2f2;
        }}
        
        .finding-card.high {{
            border-left-color: #f59e0b;
            background: #fffbeb;
        }}
        
        .finding-card.medium {{
            border-left-color: #3b82f6;
            background: #eff6ff;
        }}
        
        .finding-card.low {{
            border-left-color: #10b981;
            background: #f0fdf4;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .finding-title {{
            font-size: 1.2em;
            font-weight: 600;
            color: #1f2937;
            flex: 1;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .severity-badge.critical {{
            background: #ef4444;
            color: white;
        }}
        
        .severity-badge.high {{
            background: #f59e0b;
            color: white;
        }}
        
        .severity-badge.medium {{
            background: #3b82f6;
            color: white;
        }}
        
        .severity-badge.low {{
            background: #10b981;
            color: white;
        }}
        
        .finding-content {{
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 20px;
            align-items: start;
        }}
        
        .screenshot-thumb {{
            width: 200px;
            max-width: 100%;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            cursor: pointer;
            transition: transform 0.2s;
        }}
        
        .screenshot-thumb:hover {{
            transform: scale(1.05);
        }}
        
        .finding-details {{
            display: grid;
            gap: 10px;
        }}
        
        .detail-row {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .detail-label {{
            font-weight: 600;
            color: #6b7280;
            min-width: 120px;
        }}
        
        .detail-value {{
            color: #1f2937;
            flex: 1;
        }}
        
        .url-link {{
            color: #2563eb;
            text-decoration: none;
            word-break: break-all;
        }}
        
        .url-link:hover {{
            text-decoration: underline;
        }}
        
        .factors-list {{
            list-style: none;
            padding-left: 0;
        }}
        
        .factors-list li {{
            padding: 5px 0;
            padding-left: 20px;
            position: relative;
        }}
        
        .factors-list li:before {{
            content: "✓";
            position: absolute;
            left: 0;
            color: #10b981;
            font-weight: bold;
        }}
        
        .no-screenshot {{
            color: #9ca3af;
            font-style: italic;
        }}
        
        @media (max-width: 768px) {{
            .finding-content {{
                grid-template-columns: 1fr;
            }}
            
            .screenshot-thumb {{
                width: 100%;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ MedShield-X CTI Report</h1>
            <div class="meta">
                <strong>Brand:</strong> {brand} | 
                <strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
                <strong>Total Findings:</strong> {len(results)}
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card critical">
                <div class="stat-value">{severity_counts.get('critical', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{severity_counts.get('high', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{severity_counts.get('medium', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{severity_counts.get('low', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        {_generate_sections(by_type, output_path)}
    </div>
    
    <script>
        // Make screenshots clickable to view full size
        document.querySelectorAll('.screenshot-thumb').forEach(img => {{
            img.addEventListener('click', function() {{
                // Create modal to view full size
                const modal = document.createElement('div');
                modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.9);z-index:9999;display:flex;align-items:center;justify-content:center;cursor:pointer;';
                const fullImg = document.createElement('img');
                fullImg.src = this.src;
                fullImg.style.cssText = 'max-width:90%;max-height:90%;border-radius:8px;';
                modal.appendChild(fullImg);
                modal.addEventListener('click', () => modal.remove());
                document.body.appendChild(modal);
            }});
        }});
    </script>
</body>
</html>"""
    
    output_file.write_text(html_content, encoding='utf-8')
    logger.info(f"HTML report generated: {output_file}")

def _generate_sections(by_type: Dict[str, List[Dict[str, Any]]], output_path: str) -> str:
    """Generate HTML sections for each result type"""
    sections = []
    
    # Visual Phishing section (most important)
    if 'visual_phishing' in by_type:
        sections.append(_generate_visual_phishing_section(by_type['visual_phishing'], output_path))
    
    # Other sections
    for result_type, type_results in by_type.items():
        if result_type == 'visual_phishing':
            continue  # Already handled
        
        type_name = result_type.replace('_', ' ').title()
        sections.append(f"""
        <div class="section">
            <h2 class="section-title">{type_name} Findings ({len(type_results)})</h2>
            {_generate_findings_list(type_results, result_type)}
        </div>
        """)
    
    return '\n'.join(sections)

def _generate_visual_phishing_section(results: List[Dict[str, Any]], output_path: str = "") -> str:
    """Generate visual phishing section with Base64 embedded screenshots"""
    findings_html = []
    
    # Sort by score (highest first)
    sorted_results = sorted(results, key=lambda x: x.get('score', 0), reverse=True)
    
    for result in sorted_results:
        url = result.get('url', 'N/A')
        severity = result.get('severity', 'low')
        score = result.get('score', 0)
        screenshot_path = result.get('screenshot_path')
        
        # Get screenshot as Base64 (portable)
        screenshot_html = ""
        if screenshot_path and Path(screenshot_path).exists():
            try:
                # Read image file and encode to Base64
                with open(screenshot_path, 'rb') as img_file:
                    img_data = img_file.read()
                    img_base64 = base64.b64encode(img_data).decode('utf-8')
                    screenshot_html = f'<img src="data:image/png;base64,{img_base64}" alt="Screenshot" class="screenshot-thumb">'
                    logger.debug(f"Embedded screenshot as Base64 for {url}")
            except Exception as e:
                logger.error(f"Error encoding screenshot {screenshot_path} to Base64: {e}")
                screenshot_html = '<div class="no-screenshot">Screenshot unavailable</div>'
        else:
            screenshot_html = '<div class="no-screenshot">No screenshot available</div>'
        
        # Build details
        details = []
        if result.get('logo_detected'):
            details.append(('Logo', '✓ Detected'))
        if result.get('login_form_detected'):
            details.append(('Login Form', '⚠️ CREDENTIAL HARVESTING'))
        if result.get('keyword_matches', 0) > 0:
            keywords = ', '.join(result.get('matched_keywords', [])[:3])
            details.append(('Keywords', keywords))
        if result.get('brand_colors_detected'):
            details.append(('Colors', f"{result.get('color_match_percentage', 0):.1f}% match"))
        
        factors = result.get('factors', [])
        
        details_html = '\n'.join([
            f'<div class="detail-row"><span class="detail-label">{label}:</span><span class="detail-value">{value}</span></div>'
            for label, value in details
        ])
        
        if factors:
            factors_html = '<ul class="factors-list">' + '\n'.join([f'<li>{factor}</li>' for factor in factors]) + '</ul>'
        else:
            factors_html = ''
        
        finding_html = f"""
        <div class="finding-card {severity}">
            <div class="finding-header">
                <div class="finding-title">
                    <a href="{url}" target="_blank" class="url-link">{url}</a>
                </div>
                <div>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                    <span style="margin-left: 10px; font-weight: 600;">Score: {score:.1f}</span>
                </div>
            </div>
            <div class="finding-content">
                {screenshot_html}
                <div class="finding-details">
                    {details_html}
                    {factors_html}
                </div>
            </div>
        </div>
        """
        findings_html.append(finding_html)
    
    return f"""
    <div class="section">
        <h2 class="section-title">🎨 Visual Phishing Analysis ({len(results)})</h2>
        {''.join(findings_html)}
    </div>
    """

def _generate_findings_list(results: List[Dict[str, Any]], result_type: str) -> str:
    """Generate findings list for non-visual results"""
    findings_html = []
    
    for result in results:
        severity = result.get('severity', 'low')
        title = result.get('title', result.get('url', 'N/A'))
        url = result.get('url', result.get('href', 'N/A'))
        
        finding_html = f"""
        <div class="finding-card {severity}">
            <div class="finding-header">
                <div class="finding-title">
                    <a href="{url}" target="_blank" class="url-link">{title[:100]}</a>
                </div>
                <span class="severity-badge {severity}">{severity.upper()}</span>
            </div>
            <div class="finding-details">
                <div class="detail-row">
                    <span class="detail-label">URL:</span>
                    <span class="detail-value"><a href="{url}" target="_blank" class="url-link">{url[:150]}</a></span>
                </div>
                {_get_additional_details(result, result_type)}
            </div>
        </div>
        """
        findings_html.append(finding_html)
    
    return ''.join(findings_html)

def _get_additional_details(result: Dict[str, Any], result_type: str) -> str:
    """Get additional details based on result type"""
    details = []
    
    if result_type == 'surface_web':
        snippet = result.get('snippet', '')
        if snippet:
            details.append(('Snippet', snippet[:200] + '...' if len(snippet) > 200 else snippet))
        source = result.get('source', '')
        if source:
            details.append(('Source', source))
    
    elif result_type == 'dark_web':
        alive = result.get('alive', False)
        details.append(('Status', '✓ Alive' if alive else '✗ Offline'))
        onion = result.get('onion_address', '')
        if onion:
            details.append(('Onion Address', onion))
    
    elif result_type == 'dns_typosquatting':
        ips = result.get('ips', [])
        if ips:
            details.append(('IPs', ', '.join(ips[:5])))
        threat = result.get('threat_level', '')
        if threat:
            details.append(('Threat Level', threat))
    
    elif result_type == 'ransomware':
        group = result.get('group_name', '')
        if group:
            details.append(('Group', group))
        discovered = result.get('discovered', '')
        if discovered:
            details.append(('Discovered', discovered))
    
    return '\n'.join([
        f'<div class="detail-row"><span class="detail-label">{label}:</span><span class="detail-value">{value}</span></div>'
        for label, value in details
    ])
