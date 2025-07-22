from langchain.agents import initialize_agent, Tool
from langchain.chat_models import ChatOpenAI
from tools.jenkins_tool import run_jenkins_job
from tools.nmap_tool import run_nmap_scan
from tools.mobsf_tool import run_mobsf_scan

llm = ChatOpenAI(temperature=0)

tools = [
    Tool(name="Run Jenkins Job", func=run_jenkins_job, description="Trigger Jenkins security test"),
    Tool(name="Run Nmap Scan", func=run_nmap_scan, description="Run Nmap on a given URL"),
    Tool(name="Run MobSF Scan", func=run_mobsf_scan, description="Run MobSF scan on a mobile app"),
]

agent = initialize_agent(tools, llm, agent="zero-shot-react-description", verbose=True)
