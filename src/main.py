"""
MedShield-X - OSINT Brand Monitoring Tool
Main CLI entry point
"""
import asyncio
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Optional
import logging

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from src.core.network import NetworkClient
from src.core.ai import AIAnalyst
from src.scanners.surface import SurfaceWebScanner
from src.scanners.darkweb import DarkWebScanner
from src.scanners.dns import DNSScanner
from src.scanners.visual import VisualPhishingScanner
from src.scanners.cert_transparency import CertTransparencyScanner
from src.reporters.html import generate_html_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = typer.Typer(help="MedShield-X: OSINT Brand Monitoring Tool")
console = Console()

@app.command()
def scan(
    brand: str = typer.Option(..., "--brand", "-b", help="Brand name to monitor"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Domain to check for typosquatting"),
    surface: bool = typer.Option(True, "--surface/--no-surface", help="Enable Surface Web scan"),
    darkweb: bool = typer.Option(True, "--darkweb/--no-darkweb", help="Enable Dark Web scan"),
    dns: bool = typer.Option(True, "--dns/--no-dns", help="Enable DNS/Typosquatting scan"),
    visual: bool = typer.Option(True, "--visual/--no-visual", help="Enable Visual Phishing analysis"),
    logo_path: str = typer.Option("/app/assets/logo.png", "--logo", help="Path to brand logo image"),
    output_json: Optional[str] = typer.Option(None, "--json", "-j", help="Output JSON file path"),
    output_csv: Optional[str] = typer.Option(None, "--csv", "-c", help="Output CSV file path"),
    output_html: Optional[str] = typer.Option(None, "--html", "-h", help="Output HTML report file path"),
    tor_proxy: str = typer.Option("socks5h://tor-proxy:9050", "--tor-proxy", help="Tor SOCKS5 proxy URL"),
    cert_transparency: bool = typer.Option(True, "--ct/--no-ct", help="Enable Certificate Transparency scan"),
    ai_analysis: bool = typer.Option(True, "--ai/--no-ai", help="Enable AI analysis (requires Ollama)"),
    ollama_url: str = typer.Option("http://host.docker.internal:11434/api/generate", "--ollama-url", help="Ollama API URL"),
):
    """
    Perform comprehensive OSINT scan for brand monitoring
    """
    console.print(Panel.fit(
        f"[bold cyan]MedShield-X[/bold cyan]\n"
        f"Brand: [yellow]{brand}[/yellow]\n"
        f"Domain: [yellow]{domain or 'N/A'}[/yellow]",
        title="OSINT Scan",
        border_style="cyan"
    ))
    
    all_results = []
    
    # Ensure reports and screenshots directories exist
    reports_dir = Path("/app/reports")
    screenshots_dir = reports_dir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Screenshots directory ready: {screenshots_dir}")
    
    async def run_scans():
        """Run all enabled scans"""
        async with NetworkClient(tor_proxy=tor_proxy) as network:
            tasks = []
            
            if surface:
                console.print("\n[cyan]🔍 Starting Surface Web Scan...[/cyan]")
                surface_scanner = SurfaceWebScanner(brand)
                tasks.append(("Surface Web", surface_scanner.scan()))
            
            if darkweb:
                console.print("[cyan]🌑 Starting Dark Web Scan...[/cyan]")
                darkweb_scanner = DarkWebScanner(brand, network)
                tasks.append(("Dark Web", darkweb_scanner.scan()))
            
            if dns and domain:
                console.print("[cyan]🌐 Starting DNS/Typosquatting Scan...[/cyan]")
                dns_scanner = DNSScanner(domain)
                tasks.append(("DNS", dns_scanner.scan()))
            
            if cert_transparency and domain:
                console.print("[cyan]🔐 Starting Certificate Transparency Scan...[/cyan]")
                ct_scanner = CertTransparencyScanner(brand, domain, network)
                tasks.append(("Certificate Transparency", ct_scanner.scan()))
            
            # Run OSINT scans first
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                scan_tasks = []
                for name, task in tasks:
                    scan_tasks.append((name, task))
                
                results_dict = {}
                for name, task in scan_tasks:
                    task_progress = progress.add_task(f"Scanning {name}...", total=None)
                    try:
                        result = await task
                        results_dict[name] = result
                        progress.update(task_progress, completed=True)
                    except Exception as e:
                        logger.error(f"Scan {name} failed: {e}")
                        results_dict[name] = []
                        progress.update(task_progress, completed=True)
                
                return results_dict
    
    # Run async scans
    with console.status("[bold green]Running OSINT scans..."):
        results = asyncio.run(run_scans())
    
    # Collect OSINT results
    for scan_name, scan_results in results.items():
        all_results.extend(scan_results)
    
    # Extract suspicious domains for visual analysis (from DNS and CT scans)
    suspicious_domains = []
    if dns and domain:
        for result in results.get("DNS", []):
            if result.get('type') == 'dns_typosquatting' and result.get('threat_level') in ['high', 'medium']:
                domain_url = result.get('suspicious_domain', '')
                if domain_url:
                    suspicious_domains.append(domain_url)
    
    # Add domains from Certificate Transparency scan
    if cert_transparency and domain:
        for result in results.get("Certificate Transparency", []):
            if result.get('type') == 'cert_transparency':
                domain_url = result.get('domain', '')
                if domain_url:
                    suspicious_domains.append(domain_url)
    
    # Run Visual Phishing Scanner on suspicious domains
    if visual and suspicious_domains:
        async def run_visual_scan():
            visual_scanner = VisualPhishingScanner(
                logo_path=logo_path,
                screenshots_dir=str(screenshots_dir)
            )
            return await visual_scanner.scan_domains(suspicious_domains)
        
        with console.status("[bold green]Running visual analysis..."):
            try:
                visual_results = asyncio.run(run_visual_scan())
                all_results.extend(visual_results)
                console.print(f"[green]✓[/green] Visual analysis completed: {len(visual_results)} domains analyzed")
            except Exception as e:
                logger.error(f"Visual scanning failed: {e}")
                console.print(f"[red]✗[/red] Visual scanning failed: {e}")
    
    # Display results
    display_results(all_results, brand)
    
    # Export results
    if output_json:
        export_json(all_results, output_json)
        console.print(f"\n[green]✓[/green] Results exported to JSON: {output_json}")
    
    if output_csv:
        export_csv(all_results, output_csv)
        console.print(f"[green]✓[/green] Results exported to CSV: {output_csv}")
    
    # AI Analysis
    ai_summary = None
    if ai_analysis:
        async def run_ai_analysis():
            async with AIAnalyst(ollama_url=ollama_url) as ai:
                # Count severities
                severity_counts = {}
                for result in all_results:
                    severity = result.get('severity', 'unknown')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                # Generate executive summary
                summary = await ai.generate_summary(
                    total_findings=len(all_results),
                    critical_count=severity_counts.get('critical', 0),
                    high_count=severity_counts.get('high', 0),
                    brand=brand
                )
                return summary
        
        with console.status("[bold green]Running AI analysis..."):
            try:
                ai_summary = asyncio.run(run_ai_analysis())
                if ai_summary:
                    console.print(f"[green]✓[/green] AI analysis completed")
                else:
                    console.print(f"[yellow]⚠[/yellow] AI analysis unavailable (Ollama not accessible)")
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
                console.print(f"[yellow]⚠[/yellow] AI analysis failed: {e}")
    
    # Generate HTML report
    if output_html:
        try:
            generate_html_report(all_results, output_html, brand, ai_summary=ai_summary)
            console.print(f"[green]✓[/green] HTML report generated: {output_html}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            console.print(f"[red]✗[/red] HTML report generation failed: {e}")
    
    # Summary
    console.print("\n" + "="*60)
    console.print(f"[bold]Scan Summary:[/bold]")
    console.print(f"Total Findings: [yellow]{len(all_results)}[/yellow]")
    
    if all_results:
        severity_counts = {}
        for result in all_results:
            severity = result.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in severity_counts.items():
            color = {
                'critical': 'red',
                'high': 'yellow',
                'medium': 'blue',
                'low': 'green'
            }.get(severity, 'white')
            console.print(f"  {severity.upper()}: [{color}]{count}[/{color}]")

def display_results(results: list, brand: str):
    """Display results in rich tables"""
    if not results:
        console.print("\n[yellow]No findings detected.[/yellow]")
        return
    
    # Group by type
    by_type = {}
    for result in results:
        result_type = result.get('type', 'unknown')
        if result_type not in by_type:
            by_type[result_type] = []
        by_type[result_type].append(result)
    
    for result_type, type_results in by_type.items():
        table = Table(
            title=f"{result_type.upper().replace('_', ' ')} Findings",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
        )
        
        # Add columns based on result type
        if result_type == 'surface_web':
            table.add_column("Title", style="cyan", no_wrap=False)
            table.add_column("URL", style="blue", no_wrap=False)
            table.add_column("Severity", justify="center")
            table.add_column("Source", style="green")
            
            for result in type_results:
                severity_color = {
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'green'
                }.get(result.get('severity', 'low'), 'white')
                
                table.add_row(
                    result.get('title', 'N/A')[:50],
                    result.get('url', 'N/A')[:60],
                    f"[{severity_color}]{result.get('severity', 'unknown')}[/{severity_color}]",
                    result.get('source', 'N/A')
                )
        
        elif result_type == 'dark_web':
            table.add_column("Type", style="cyan")
            table.add_column("URL/Address", style="blue", no_wrap=False)
            table.add_column("Alive", justify="center")
            table.add_column("Severity", justify="center")
            
            for result in type_results:
                alive_status = "[green]✓[/green]" if result.get('alive') else "[red]✗[/red]"
                severity = result.get('severity', 'medium')
                severity_color = 'red' if severity == 'critical' else 'yellow' if severity == 'high' else 'blue'
                
                table.add_row(
                    result.get('source', 'N/A'),
                    result.get('url', result.get('onion_address', 'N/A'))[:60],
                    alive_status,
                    f"[{severity_color}]{severity}[/{severity_color}]"
                )
        
        elif result_type == 'dns_typosquatting':
            table.add_column("Suspicious Domain", style="red", no_wrap=False)
            table.add_column("IPs", style="yellow", no_wrap=False)
            table.add_column("Threat Level", justify="center")
            
            for result in type_results:
                ips = ', '.join(result.get('ips', []))[:40] or 'N/A'
                threat = result.get('threat_level', 'medium')
                threat_color = 'red' if threat == 'high' else 'yellow'
                
                table.add_row(
                    result.get('suspicious_domain', 'N/A'),
                    ips,
                    f"[{threat_color}]{threat}[/{threat_color}]"
                )
        
        elif result_type == 'ransomware':
            table.add_column("Group", style="red", no_wrap=False)
            table.add_column("Post Title", style="yellow", no_wrap=False)
            table.add_column("URL", style="blue", no_wrap=False)
            table.add_column("Discovered", style="cyan")
            
            for result in type_results:
                table.add_row(
                    result.get('group_name', 'N/A'),
                    result.get('post_title', 'N/A')[:40],
                    result.get('url', 'N/A')[:50],
                    result.get('discovered', 'N/A')
                )
        
        elif result_type == 'cert_transparency':
            table.add_column("Domain", style="red", no_wrap=False)
            table.add_column("Source", style="cyan")
            table.add_column("Severity", justify="center")
            
            for result in type_results:
                severity = result.get('severity', 'high')
                severity_color = 'red' if severity == 'high' else 'yellow'
                
                table.add_row(
                    result.get('domain', 'N/A'),
                    result.get('source', 'N/A'),
                    f"[{severity_color}]{severity}[/{severity_color}]"
                )
        
        elif result_type == 'visual_phishing':
            table.add_column("Domain", style="red", no_wrap=False)
            table.add_column("Score", justify="center")
            table.add_column("Severity", justify="center")
            table.add_column("Logo", justify="center")
            table.add_column("Keywords", style="yellow", no_wrap=False)
            
            # Sort by score (highest first)
            type_results.sort(key=lambda x: x.get('score', 0), reverse=True)
            
            for result in type_results:
                score = result.get('score', 0)
                severity = result.get('severity', 'low')
                logo_detected = result.get('logo_detected', False)
                keywords = result.get('matched_keywords', [])
                
                severity_color = {
                    'critical': 'red',
                    'high': 'yellow',
                    'medium': 'blue',
                    'low': 'green'
                }.get(severity, 'white')
                
                logo_status = "[red]✓[/red]" if logo_detected else "[dim]✗[/dim]"
                keywords_str = ', '.join(keywords[:3]) if keywords else 'None'
                
                table.add_row(
                    result.get('url', 'N/A')[:50],
                    f"[bold]{score:.1f}[/bold]",
                    f"[{severity_color}]{severity.upper()}[/{severity_color}]",
                    logo_status,
                    keywords_str[:40]
                )
        
        console.print("\n")
        console.print(table)

def export_json(results: list, filepath: str):
    """Export results to JSON"""
    output = {
        'scan_timestamp': datetime.now().isoformat(),
        'total_findings': len(results),
        'findings': results
    }
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

def export_csv(results: list, filepath: str):
    """Export results to CSV"""
    if not results:
        return
    
    # Get all unique keys from results
    all_keys = set()
    for result in results:
        all_keys.update(result.keys())
    
    fieldnames = ['type', 'severity'] + sorted([k for k in all_keys if k not in ['type', 'severity']])
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        for result in results:
            # Flatten nested structures
            row = {}
            for key, value in result.items():
                if isinstance(value, (list, dict)):
                    row[key] = json.dumps(value)
                else:
                    row[key] = value
            writer.writerow(row)

@app.command()
def test_tor():
    """Test Tor proxy connection"""
    console.print("[cyan]Testing Tor proxy connection...[/cyan]")
    
    async def test():
        async with NetworkClient() as network:
            # Try to access a .onion test site
            test_url = "http://3g2upl4pq6kufc4m.onion"  # DuckDuckGo .onion
            console.print(f"Testing connection to: {test_url}")
            
            response = await network.get(test_url)
            if response:
                console.print(f"[green]✓[/green] Tor proxy is working! Status: {response.status}")
            else:
                console.print("[red]✗[/red] Tor proxy connection failed")
    
    asyncio.run(test())

if __name__ == "__main__":
    app()

