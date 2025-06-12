import os, json, requests
from pathlib import Path
from tenacity import retry, stop_after_attempt, wait_exponential

LANGCHAIN_ENDPOINT = os.getenv("LANGCHAIN_API_ENDPOINT", "https://api.langchain.io")
OLLAMA_ENDPOINT = os.getenv("OLLAMA_API_ENDPOINT", "http://localhost:8080")

@retry(stop=stop_after_attempt(3), wait=wait_exponential())
def langchain_scan(code):
    try:
        response = requests.post(
            f"{LANGCHAIN_ENDPOINT}/api/v1/analyze",
            headers={
                "Authorization": f"Bearer {os.environ['LANGCHAIN_API_KEY']}",
                "Content-Type": "application/json"
            },
            json={"code": code, "scan_type": "BOLA"},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

@retry(stop=stop_after_attempt(3), wait=wait_exponential())
def ollama_scan(code):
    try:
        prompt = f"Check this code for OWASP API1:2023 BOLA issues:\n\n{code[:5000]}"
        headers = {"Content-Type": "application/json"}
        if os.getenv("OLLAMA_API_KEY"):
            headers["Authorization"] = f"Bearer {os.environ['OLLAMA_API_KEY']}"        
        response = requests.post(
            f"{OLLAMA_ENDPOINT}/api/generate",
            headers=headers,
            json={"model": "llama3", "prompt": prompt, "stream": False},
            timeout=45
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def main():
    try:
        if not os.environ.get("LANGCHAIN_API_KEY"):
            raise ValueError("Missing LANGCHAIN_API_KEY environment variable")

        files = []
        try:
            files = json.loads(os.environ.get("TARGET_FILES", "[]"))
        except json.JSONDecodeError:
            print("⚠️ Invalid JSON in TARGET_FILES environment variable")

        if not files:
            print("⚠️ No files provided in TARGET_FILES.")
            return

        results = []
        vulnerabilities = []
        scan_errors = []

        for file in files:
            if not os.path.exists(file):
                scan_errors.append(f"File not found: {file}")
                continue

            try:
                with open(file, 'r') as f:
                    code = f.read()
            except Exception as e:
                scan_errors.append(f"Error reading {file}: {str(e)}")
                continue

            lc_result = langchain_scan(code)
            ol_result = ollama_scan(code)
            results.append({"file": file, "langchain": lc_result, "ollama": ol_result})

            print(f"🔍 LangChain result for {file}:", json.dumps(lc_result, indent=2))
            print(f"🤖 Ollama result for {file}:", json.dumps(ol_result, indent=2))

            if "error" not in lc_result:
                vulns = lc_result.get("vulnerabilities") or lc_result.get("bola_vulnerabilities") or []
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        vulnerabilities.append({
                            "file": file,
                            "line": vuln.get("line", 1),
                            "severity": vuln.get("severity", "warning"),
                            "description": vuln.get("description", "BOLA vulnerability detected")
                        })

            if "error" not in ol_result:
                response_text = ol_result.get("response", "")
                if "BOLA" in response_text or "Broken Object" in response_text:
                    vulnerabilities.append({
                        "file": file,
                        "line": 1,
                        "severity": "warning",
                        "description": "Potential BOLA vulnerability detected by AI model"
                    })

        with open("bola-results.json", "w") as f:
            json.dump({"results": results, "errors": scan_errors}, f, indent=2)

        print(f"🧠 Extracted vulnerabilities: {json.dumps(vulnerabilities, indent=2)}")

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
                }]
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

        if scan_errors:
            print("\n⛔️ Scan errors:")
            for error in scan_errors:
                print(f"  - {error}")

        if vulnerabilities:
            print(f"\n❌ Found {len(vulnerabilities)} BOLA vulnerabilities")
            exit(1)
        else:
            print("\n✅ No BOLA vulnerabilities found")

    except Exception as e:
        print(f"❌ Fatal error: {e}")
        exit(1)

if __name__ == "__main__":
    main()
