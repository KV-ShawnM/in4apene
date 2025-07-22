import os
import gradio as gr
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from langchain.agents import initialize_agent, Tool
from langchain.chat_models import ChatOpenAI

from dotenv import load_dotenv
load_dotenv()


# Dummy tool functions for testing
def run_jenkins_job(input: str) -> str:
    return f"Triggered Jenkins job with input: {input}"

def run_nmap_scan(input: str) -> str:
    return f"Performed Nmap scan on: {input}"

def run_mobsf_scan(input: str) -> str:
    return f"Performed MobSF scan on: {input}"

# Initialize LangChain agent
llm = ChatOpenAI(temperature=0)
tools = [
    Tool(name="Run Jenkins Job", func=run_jenkins_job, description="Trigger Jenkins security test"),
    Tool(name="Run Nmap Scan", func=run_nmap_scan, description="Run Nmap on a given URL"),
    Tool(name="Run MobSF Scan", func=run_mobsf_scan, description="Run MobSF scan on a mobile app"),
]
agent = initialize_agent(tools, llm, agent="zero-shot-react-description", verbose=True)

# Gradio function
def agent_response(user_input):
    return agent.run(user_input)

# Gradio UI
gradio_interface = gr.Interface(fn=agent_response, inputs="text", outputs="text", title="Security Testing Agent")

# FastAPI app
app = FastAPI()
app = gr.mount_gradio_app(app, gradio_interface, path="/gradio")

# CORS for API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API endpoint
@app.post("/api/agent")
async def query_agent(request: Request):
    data = await request.json()
    user_input = data.get("message", "")
    response = agent_response(user_input)
    return {"response": response}
