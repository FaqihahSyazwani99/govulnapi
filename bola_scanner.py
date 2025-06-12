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
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def main():
    try:
        files = json.loads(os.environ.get("TARGET_FILES", "[]"))
        if not files:
            print("⚠️ No files provided in TARGET_FILES.")
            return

        results = []
        vulnerabilities = []

        for file in files:
            if not os.path.exists(file):
                continue
            with open(file, 'r') as f:
                code = f.read()

            lc_result = langchain_scan(code)
            ol_result = ollama_scan(code)
            result = {"file": file, "langchain": lc_result, "ollama": ol_result}
            results.append(result)

            for response in [lc_result, ol_result]:
                vulns = response.get("vulnerabilities") or response.get("bola_vulnerabilities")
                if vulns:
                    for vuln in vulns:
                        vuln["file"] = file
                        vulnerabilities.append(vuln)

        with open("bola-results.json", "w") as f:
            json.dump(results, f, indent=2)

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "BOLA Scanner",
                        "rules": [{
                            "id": "BOLA",
                            "name": "Broken Object Level Authorization",
                            "shortDescription": {"text": "API1:2023 BOLA"},
                            "fullDescription": {"text": "Improper object-level access control in APIs."},
                            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                        }]
                    }
                },
                "results": [
                    {
                        "ruleId": "BOLA",
                        "level": vuln.get("severity", "warning"),
                        "message": {"text": vuln.get("description", "BOLA issue detected.")},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": vuln.get("file")},
                                "region": {"startLine": vuln.get("line", 1)}
                            }
                        }]
                    }
                    for vuln in vulnerabilities
                ]
            }]
        }

        with open("bola-results.sarif", "w") as f:
            json.dump(sarif, f, indent=2)

        if vulnerabilities:
            print(f"❌ Found {len(vulnerabilities)} BOLA vulnerabilities.")
            exit(1)
        else:
            print("✅ No BOLA vulnerabilities found.")

    except Exception as e:
        print(f"❌ Fatal error: {e}")
        exit(1)

if __name__ == "__main__":
    main()
