import os
import json
import click
from pathlib import Path
from typing import Dict, Any
from .core.risk_calculator import EnhancedContextualFramework, VulnerabilityData
import logging

logging.basicConfig(level=logging.INFO)


def validate_output_path(file_path: str) -> Path:
    """
    Validate output file path to prevent path traversal attacks.
    
    Security: Ensures output files are only created in current directory
    or subdirectories, preventing directory traversal attacks.
    
    Args:
        file_path: User-provided output file path
        
    Returns:
        Validated Path object
        
    Raises:
        click.BadParameter: If path is outside current directory
    """
    abs_path = Path(file_path).resolve()
    cwd = Path.cwd().resolve()
    
    try:
        abs_path.relative_to(cwd)
    except ValueError:
        raise click.BadParameter(
            "Output file must be in current directory or subdirectories. "
            "Path traversal is not allowed."
        )
    
    return abs_path


def sanitize_output_data(result, cve: str, framework: str, 
                         cvss: float, criticality: int, 
                         epss: float, internet_facing: bool) -> Dict[str, Any]:
    """
    Create sanitized output dictionary without sensitive data.
    
    Security: Removes any sensitive information that shouldn't be exposed
    in JSON output (API keys, internal paths, user identifiers).
    
    Args:
        result: Risk calculation result object
        cve: CVE identifier
        framework: Framework name
        cvss: CVSS score
        criticality: Asset criticality
        epss: EPSS score
        internet_facing: Internet facing flag
        
    Returns:
        Sanitized dictionary safe for JSON output
    """
    output = {
        "cve_id": str(cve).strip(),
        "risk_score": float(result.score),
        "priority": str(result.priority),
        "timeline_days": int(result.timeline_days),
        "explanation": str(result.explanation),
        "components": dict(result.components),
        "framework": str(framework),
        "input_parameters": {
            "cvss_score": float(cvss),
            "asset_criticality": int(criticality),
            "epss_score": float(epss),
            "is_internet_facing": bool(internet_facing)
        }
    }
    
    # Add optional fields if they exist
    if hasattr(result, 'recommendations'):
        output['recommendations'] = list(result.recommendations)
    
    if hasattr(result, 'calculation_breakdown'):
        output['calculation_breakdown'] = dict(result.calculation_breakdown)
    
    if hasattr(result, 'confidence_score'):
        output['confidence_score'] = float(result.confidence_score)
    
    return output


def write_json_securely(file_path: Path, data: Dict[str, Any], 
                        max_size_mb: int = 10) -> None:
    """
    Write JSON data to file with security controls.
    
    Security measures:
    - Size limit to prevent DoS
    - Restrictive file permissions (0o600 = owner read/write only)
    - O_EXCL flag prevents race conditions
    - Atomic write operation
    
    Args:
        file_path: Path to output file
        data: Dictionary to serialize as JSON
        max_size_mb: Maximum file size in MB (default: 10MB)
        
    Raises:
        ValueError: If output exceeds size limit
        FileExistsError: If file already exists
        PermissionError: If lacking write permissions
    """
    json_str = json.dumps(data, indent=2, ensure_ascii=True)
    
    # Security: Prevent DoS via large file creation
    size_bytes = len(json_str.encode('utf-8'))
    if size_bytes > max_size_mb * 1024 * 1024:
        raise ValueError(f"Output exceeds {max_size_mb}MB limit")
    
    # Security: Create file with restrictive permissions (owner read/write only)
    # O_EXCL ensures atomic creation (fails if file exists)
    fd = os.open(
        file_path, 
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600
    )
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(json_str)
    except Exception:
        os.close(fd)
        raise


@click.group()
def cli() -> None:
    """VulnRisk - Contextual Vulnerability Risk Scoring"""
    pass


@cli.command()
@click.option('--cve', required=True, help='CVE identifier')
@click.option('--cvss', required=True, type=float, help='CVSS score (0-10)')
@click.option('--criticality', required=True, type=int, help='Asset criticality (1-10)')
@click.option('--epss', required=True, type=float, help='EPSS score (0-1)')
@click.option('--internet-facing', is_flag=True, help='Asset is internet-facing')
@click.option('--framework', default='enhanced', help='Risk framework to use')
@click.option('--format', 
              default='text', 
              type=click.Choice(['text', 'json'], case_sensitive=False),
              help='Output format (text or json)')
@click.option('--output-file', 
              type=click.Path(),
              help='Save output to file (must be in current directory or subdirectories)')
def score(cve: str, cvss: float, criticality: int, epss: float, 
          internet_facing: bool, framework: str, format: str, 
          output_file: str) -> None:
    """
    Calculate risk score for a single vulnerability.
    
    Examples:
        # Text output (default)
        vulnrisk score --cve CVE-2024-1234 --cvss 9.8 --criticality 10 --epss 0.95 --internet-facing
        
        # JSON output to stdout
        vulnrisk score --cve CVE-2024-1234 --cvss 9.8 --criticality 10 --epss 0.95 --format json
        
        # JSON output to file
        vulnrisk score --cve CVE-2024-1234 --cvss 9.8 --criticality 10 --epss 0.95 --format json --output-file results.json
    """
    try:
        # Input validation (OWASP A03:2021 - Injection Prevention)
        if not (0 <= cvss <= 10):
            raise ValueError("CVSS score must be between 0 and 10.")
        if not (1 <= criticality <= 10):
            raise ValueError("Asset criticality must be between 1 and 10.")
        if not (0 <= epss <= 1):
            raise ValueError("EPSS score must be between 0 and 1.")

        # Create vulnerability data
        vuln = VulnerabilityData(
            cve_id=cve,
            cvss_score=cvss,
            asset_criticality=criticality,
            epss_score=epss,
            is_internet_facing=internet_facing
        )

        # Select framework
        if framework == 'enhanced':
            calculator = EnhancedContextualFramework()
        else:
            click.echo(f"Framework '{framework}' not supported yet")
            raise SystemExit(1)

        # Calculate risk
        result = calculator.calculate_risk(vuln)

        # Output based on format
        if format.lower() == 'json':
            # Sanitize output data (prevent information disclosure)
            output_data = sanitize_output_data(
                result, cve, framework, cvss, criticality, epss, internet_facing
            )
            
            if output_file:
                # Validate path (OWASP A01:2021 - Broken Access Control)
                safe_path = validate_output_path(output_file)
                
                # Write securely (NIST SP 800-218 - Secure data protection)
                write_json_securely(safe_path, output_data)
                click.echo(f"Results saved to {safe_path}")
            else:
                # Print to stdout
                click.echo(json.dumps(output_data, indent=2))
        else:
            # Text output (existing format)
            click.echo(f"\n🎯 Risk Assessment for {cve}")
            click.echo(f"Score: {result.score:.2f}")
            click.echo(f"Priority: {result.priority}")
            click.echo(f"Remediation Timeline: {result.timeline_days} days")
            click.echo(f"\nExplanation:\n{result.explanation}")
            
    except ValueError as e:
        # Known validation errors - safe to display
        click.echo(f"Input validation error: {str(e)}", err=True)
        raise SystemExit(1)
    except click.BadParameter as e:
        # Path validation errors - safe to display
        click.echo(f"Error: {str(e)}", err=True)
        raise SystemExit(1)
    except FileExistsError:
        # File already exists
        click.echo("Error: Output file already exists. Choose a different name or remove the existing file.", err=True)
        raise SystemExit(1)
    except PermissionError:
        # Permission denied
        click.echo("Error: Permission denied writing to output file.", err=True)
        raise SystemExit(1)
    except Exception as e:
        # Unknown errors - don't expose internal details (security best practice)
        logging.error(f"Error calculating risk: {e}")
        click.echo("An error occurred. Please check your input values.", err=True)
        raise SystemExit(2)


if __name__ == '__main__':
    cli() 