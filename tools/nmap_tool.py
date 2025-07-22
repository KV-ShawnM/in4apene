import subprocess

def run_nmap_scan(url: str) -> str:
    result = subprocess.run(["nmap", "-sV", url], capture_output=True, text=True)
    return result.stdout
