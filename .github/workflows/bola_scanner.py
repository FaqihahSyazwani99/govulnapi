import os
import json
import requests
import logging
from pathlib import Path
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from socket import gaierror
from urllib3.exceptions import NameResolutionError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Configuration - moved inside main to handle validation better
MAX_FILE_SIZE = 1024 * 1024 * 2  # 2MB
SUPPORTED_EXTENSIONS = {'.go', '.js', '.py', '.java', '.ts', '.rs', '.rb'}

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
    reraise=True
)
def langchain_scan(code, endpoint, api_key):
    try:
        response = requests.post(
            f"{endpoint}/api/v1/analyze",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={"code": code, "scan_type": "BOLA"},
            timeout=20
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"LangChain scan failed: {str(e)}")
        return {"error": str(e), "type": "connection" if isinstance(e, requests.exceptions.ConnectionError) else "api"}

@retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=1, max=5),
    retry=retry_if_exception_type(requests.exceptions.ConnectionError),
    reraise=True
)
def ollama_scan(code, endpoint, api_key=None):
    try:
        prompt = f"Check this code for OWASP API1:2023 BOLA issues:\n\n{code[:5000]}"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        response = requests.post(
            f"{endpoint}/api/generate",
            headers=headers,
            json={"model": "llama3", "prompt": prompt, "stream": False},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Ollama scan failed: {str(e)}")
        return {"error": str(e), "type": "connection" if isinstance(e, requests.exceptions.ConnectionError) else "api"}

def should_scan_file(file_path):
    if not os.path.exists(file_path):
        return False, "File not found"
    
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return False, f"Unsupported file extension: {ext}"
    
    try:
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            return False, f"File too large ({file_size} bytes)"
    except Exception as e:
        return False, f"Error checking file size: {str(e)}"
    
    return True, ""

def main():
    try:
        # Validate configuration
        langchain_endpoint = os.getenv("LANGCHAIN_API_ENDPOINT")
        langchain_api_key = os.getenv("LANGCHAIN_API_KEY")
        ollama_endpoint = os.getenv("OLLAMA_API_ENDPOINT", "http://localhost:11434")
        enable_ollama = os.getenv("ENABLE_OLLAMA", "false").lower() == "true"
        target_files = os.getenv("TARGET_FILES", "[]")
        
        # Validate required config
        if not langchain_endpoint or not langchain_api_key:
            raise ValueError("Missing required environment variables: LANGCHAIN_API_ENDPOINT and LANGCHAIN_API_KEY must be set")
        
        try:
            files = json.loads(target_files)
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON in TARGET_FILES environment variable")

        logger.info(f"Starting BOLA scan on {len(files)} files")
        logger.info(f"LangChain endpoint: {langchain_endpoint}")
        logger.info(f"Ollama enabled: {enable_ollama}, Ollama endpoint: {ollama_endpoint}")

        results = []
        vulnerabilities = []
        scan_errors = []
        skipped_files = []
        langchain_disabled = False

        for file_path in files:
            # Check if file should be scanned
            valid, reason = should_scan_file(file_path)
            if not valid:
                skipped_files.append(f"{file_path}: {reason}")
                continue

            try:
                # Read file content
                with open(file_path, 'r') as f:
                    code = f.read(MAX_FILE_SIZE)
                
                file_result = {"file": file_path}
                
                # Run LangChain scan unless previously disabled
                if not langchain_disabled:
                    lc_result = langchain_scan(code, langchain_endpoint, langchain_api_key)
                    file_result["langchain"] = lc_result
                    
                    # If connection error, disable further LangChain scans
                    if lc_result.get("type") == "connection":
                        logger.warning("Disabling LangChain scans due to connection error")
                        langchain_disabled = True
                    
                    # Process vulnerabilities
                    if "error" not in lc_result:
                        vulns = lc_result.get("vulnerabilities") or lc_result.get("bola_vulnerabilities") or []
                        for vuln in vulns:
                            if isinstance(vuln, dict):
                                vulnerabilities.append({
                                    "file": file_path,
                                    "line": vuln.get("line", 1),
                                    "severity": vuln.get("severity", "medium"),
                                    "description": vuln.get("description", "Potential BOLA vulnerability"),
                                    "source": "langchain"
                                })
                else:
                    file_result["langchain"] = {"info": "Skipped due to previous connection errors"}
                
                # Run Ollama scan if enabled
                if enable_ollama:
                    ol_result = ollama_scan(code, ollama_endpoint, os.getenv("OLLAMA_API_KEY"))
                    file_result["ollama"] = ol_result
                    
                    # Process vulnerabilities
                    if "error" not in ol_result:
                        response_text = ol_result.get("response", "")
                        if "BOLA" in response_text or "Broken Object" in response_text:
                            vulnerabilities.append({
                                "file": file_path,
                                "line": 1,
                                "severity": "medium",
                                "description": "AI-detected potential BOLA vulnerability",
                                "source": "ollama"
                            })
                else:
                    file_result["ollama"] = {"info": "Ollama disabled"}
                
                results.append(file_result)
                logger.info(f"Scanned {file_path}")

            except Exception as e:
                scan_errors.append(f"Error processing {file_path}: {str(e)}")
                logger.exception(f"Failed to scan {file_path}")

        # Generate output files
        output_data = {
            "results": results,
            "vulnerabilities": vulnerabilities,
            "errors": scan_errors,
            "skipped_files": skipped_files,
            "stats": {
                "scanned": len(results),
                "vulnerabilities": len(vulnerabilities),
                "errors": len(scan_errors),
                "skipped": len(skipped_files)
            }
        }
        
        with open("bola-results.json", "w") as f:
            json.dump(output_data, f, indent=2)

        # Generate SARIF output
        sarif_results = []
        for vuln in vulnerabilities:
            sarif_results.append({
                "ruleId": "BOLA",
                "level": vuln["severity"],
                "message": {"text": vuln["description"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": vuln["file"]},
                        "region": {
                            "startLine": vuln["line"],
                            "startColumn": 1,
                            "endColumn": 1
                        }
                    }
                }],
                "properties": {
                    "source": vuln.get("source", "unknown")
                }
            })
        
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "BOLA Scanner",
                        "informationUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        "rules": [{
                            "id": "BOLA",
                            "name": "Broken Object Level Authorization",
                            "shortDescription": {"text": "API1:2023 BOLA"},
                            "fullDescription": {"text": "Improper object-level access control in APIs."},
                            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                            "properties": {"category": "security"}
                        }]
                    }
                },
                "results": sarif_results
            }]
        }

        with open("bola-results.sarif", "w") as f:
            json.dump(sarif, f, indent=2)

        # Print summary
        logger.info("\n=== Scan Summary ===")
        logger.info(f"Files scanned: {len(results)}")
        logger.info(f"Files skipped: {len(skipped_files)}")
        logger.info(f"Vulnerabilities found: {len(vulnerabilities)}")
        logger.info(f"Errors encountered: {len(scan_errors)}")
        
        if skipped_files:
            logger.info("\nSkipped files:")
            for item in skipped_files:
                logger.info(f"  - {item}")
        
        if scan_errors:
            logger.info("\nScan errors:")
            for error in scan_errors:
                logger.info(f"  - {error}")
        
        if vulnerabilities:
            logger.info("\nVulnerabilities found:")
            for vuln in vulnerabilities:
                logger.info(f"  - {vuln['file']}:{vuln['line']} - {vuln['description']}")
            logger.error("❌ BOLA vulnerabilities detected")
            exit(1)
        else:
            logger.info("✅ No BOLA vulnerabilities found")
            exit(0)

    except Exception as e:
        logger.exception("❌ Fatal error during scan execution")
        exit(1)

if __name__ == "__main__":
    main()