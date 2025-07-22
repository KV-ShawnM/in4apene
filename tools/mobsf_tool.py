import os
import requests

def run_mobsf_scan(file_path: str) -> str:
    mobsf_url = os.getenv("MOBSF_URL")
    mobsf_api_key = os.getenv("MOBSF_API_KEY")

    headers = {
        "Authorization": mobsf_api_key
    }

    with open(file_path, "rb") as f:
        files = {"file": f}
        upload_response = requests.post(f"{mobsf_url}/api/v1/upload", headers=headers, files=files)

    if upload_response.status_code != 200:
        return f"Failed to upload file to MobSF. Status code: {upload_response.status_code}"

    scan_data = upload_response.json()
    scan_hash = scan_data.get("hash")

    scan_response = requests.post(f"{mobsf_url}/api/v1/scan", headers=headers, json={"hash": scan_hash})
    if scan_response.status_code == 200:
        return f"MobSF scan completed successfully. Report URL: {mobsf_url}/scan/view/{scan_hash}"
    else:
        return f"MobSF scan failed. Status code: {scan_response.status_code}, Response: {scan_response.text}"
