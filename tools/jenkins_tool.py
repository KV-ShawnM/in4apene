import os
import requests

def run_jenkins_job(job_name: str) -> str:
    jenkins_url = os.getenv("JENKINS_URL")
    jenkins_user = os.getenv("JENKINS_USER")
    jenkins_token = os.getenv("JENKINS_API_TOKEN")

    job_url = f"{jenkins_url}/job/{job_name}/build"
    response = requests.post(job_url, auth=(jenkins_user, jenkins_token))

    if response.status_code == 201:
        return f"Jenkins job '{job_name}' triggered successfully."
    else:
        return f"Failed to trigger Jenkins job '{job_name}'. Status code: {response.status_code}, Response: {response.text}"
