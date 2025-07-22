import os
import requests


def run_jenkins_job(endpoint) -> str:
    jenkins_url = os.getenv("JENKINS_URL")
    jenkins_user = os.getenv("JENKINS_USER")
    jenkins_token = os.getenv("JENKINS_API_TOKEN")
    job_name = os.getenv("JENKINS_JOB_NAME")

    job_url = f"{jenkins_url}/job/{job_name}/buildWithParameters"
    response = requests.post(
        job_url,
        auth=(jenkins_user, jenkins_token),
        data={
            "ENDPOINT": endpoint,
            "SCNTYP": "Port scan",
        },
    )

    if response.status_code == 201:
        return f"Jenkins job '{job_name}' triggered successfully."
    else:
        return f"Failed to trigger Jenkins job '{job_name}'. Status code: {response.status_code}"
