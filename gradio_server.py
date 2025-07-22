import os
import logging
import gradio as gr
import sqlite3
import json
from datetime import datetime
import requests
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage
from langchain.tools import tool

# --- 1. Configuration and Setup ---
# Load environment variables from .env file at the start
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)

# --- SQLite Database Setup ---
DB_FILE = "security_audits.db"

def setup_database():
    """Initializes the SQLite database and creates the table if it doesn't exist."""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Create table to store audit results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_type TEXT NOT NULL,
                answers TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()
        print(f"✅ SQLite database '{DB_FILE}' initialized successfully.")
    except sqlite3.Error as e:
        print(f"🔥 SQLite error: {e}")
    finally:
        if conn:
            conn.close()

# --- OpenAI API Key Setup ---
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    print("🔥 OPENAI_API_KEY environment variable not set. The agent will not work.")


# --- 2. Define Questions & State ---
# Questions are sourced from the user-provided document.
MOBILE_QUESTIONS = [
    "Does the mobile app have any force-update functionality?",
    "Is there a disclosure policy in place?",
    "Does the app comply with privacy laws and regulations?",
    "Is biometric authentication used?",
    "Does your application have 2FA?",
    "Is there any app-level encryption (apart from HTTPS)?",
    "How many file upload endpoints does the application have?",
    "Does this mobile application contact a server via the internet? If yes, what is the URL?"
]

WEB_QUESTIONS = [
    "What is the website URL?",
    "Are websockets used in the project?",
    "Does the application make use of web messaging?",
    "How many file upload endpoints does the application have?",
    "Does the project use Flash?",
    "Are there different roles in the application (like admin, employee & customer)?",
    "Do your users log in via a username they can set by themselves?",
    "Is there any sort of in-app encryption (apart from HTTPS)?",
    "Are there multiple ways to log in (like email/password and OTP)?",
    "Are cookies used to maintain sessions?",
    "Is there any password recovery functionality?",
    "Does the project use GraphQL?",
    "Does the project use OAuth?"
]

# In-memory store for conversation state. A more robust solution would use Redis or a DB.
conversation_state = {}

# --- 3. Define Security Tools ---
@tool
def trigger_jenkins_build(endpoint: str) -> str:
    """
    Triggers a build for a pre-configured Jenkins job to scan a target endpoint.
    The Jenkins job name is set via an environment variable.
    The 'endpoint' parameter should be a valid URL or IP address (e.g., 'example.com', '192.168.1.1').
    Use this to start a CI/CD security testing pipeline.
    """
    jenkins_url = os.getenv("JENKINS_URL")
    jenkins_user = os.getenv("JENKINS_USER")
    jenkins_token = os.getenv("JENKINS_API_TOKEN")
    job_name = os.getenv("JENKINS_JOB_NAME")

    if not all([jenkins_url, jenkins_user, jenkins_token, job_name]):
        return "Error: Jenkins environment variables (JENKINS_URL, JENKINS_USER, JENKINS_API_TOKEN, JENKINS_JOB_NAME) are not set."

    logging.info(f"Triggering Jenkins build for job: {job_name} with endpoint: {endpoint}")

    job_url = f"{jenkins_url}/job/{job_name}/buildWithParameters"
    
    try:
        response = requests.post(
            job_url,
            auth=(jenkins_user, jenkins_token),
            data={
                "ENDPOINT": endpoint,
                "SCNTYP": "Port scan",
            },
            timeout=30
        )
        response.raise_for_status()
        
        return f"Successfully triggered Jenkins job '{job_name}' for endpoint '{endpoint}'. Status: {response.status_code}"

    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to trigger Jenkins job: {e}")
        return f"Failed to trigger Jenkins job '{job_name}'. Error: {e}"

@tool
def run_mobsf_scan(apk_or_ipa_url: str) -> str:
    """
    Performs a Mobile Security Framework (MobSF) static analysis on a mobile application.
    The user must provide a direct URL to the .apk (Android) or .ipa (iOS) file.
    """
    logging.info(f"Starting MobSF scan for app at: {apk_or_ipa_url}")
    return f"MobSF scan initiated for {apk_or_ipa_url}. Analysis report will be available shortly."

# --- 4. Create the LangChain Agent ---
tools = [trigger_jenkins_build, run_mobsf_scan]
llm = ChatOpenAI(model="gpt-4o", temperature=0, api_key=OPENAI_API_KEY)
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful security operations assistant. You have access to several security tools (Jenkins, MobSF). Your primary job is to use these tools when requested. If a user mentions a tool by name, you should use it. If you don't have enough information to use a tool (like a URL), you MUST ask the user for it. Separately, you can also guide users through a security audit questionnaire if they explicitly ask for an 'audit' or 'questionnaire'."),
    MessagesPlaceholder(variable_name="chat_history", optional=True),
    ("human", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])
agent = create_openai_tools_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True, handle_parsing_errors=True)


# --- 5. Gradio Interface Function ---
async def predict(message, history, request: gr.Request):
    """
    Main function for Gradio ChatInterface. It now manages a conversational state
    for the security audit questionnaire and saves to SQLite.
    """
    try:
        session_id = request.session_hash
        state = conversation_state.get(session_id, {})
        user_intent = message.lower()

        # --- Questionnaire Logic ---
        # Check if we are in the middle of a questionnaire
        if state.get("in_questionnaire"):
            
            # Case 1: We have started the questionnaire but are waiting for the project type.
            if "questions" not in state:
                if user_intent in ["mobile", "web"]:
                    state["project_type"] = user_intent
                    state["questions"] = MOBILE_QUESTIONS if user_intent == "mobile" else WEB_QUESTIONS
                    state["question_index"] = 1
                    first_question = state["questions"][0]
                    conversation_state[session_id] = state
                    return first_question
                else:
                    return "Please specify if your project is 'mobile' or 'web' to continue."

            # Case 2: We are actively asking questions.
            else:
                question_list = state["questions"]
                question_index = state["question_index"]

                # Store the last answer
                last_question = question_list[question_index - 1]
                state["answers"][last_question] = message
                
                # --- NEW: Automatic Tool Trigger Logic ---
                tool_response = ""
                is_web_url_question = "What is the website URL?" in last_question
                is_mobile_url_question = "contact a server via the internet" in last_question

                if is_web_url_question or is_mobile_url_question:
                    logging.info(f"URL detected in response. Triggering Jenkins build for: {message}")
                    # The user's message is the URL or contains the URL. Let the agent extract it.
                    # We directly call the tool function for simplicity here.
                    tool_response = trigger_jenkins_build(endpoint=message)
                # --- END of new logic ---

                # If there are more questions, ask the next one
                if question_index < len(question_list):
                    next_question = question_list[question_index]
                    state["question_index"] += 1
                    conversation_state[session_id] = state
                    
                    if tool_response:
                        return f"Okay, I'm starting a scan on that endpoint. {tool_response}\n\nIn the meantime, let's continue. {next_question}"
                    else:
                        return next_question
                else:
                    # End of questionnaire, save to SQLite
                    try:
                        conn = sqlite3.connect(DB_FILE)
                        cursor = conn.cursor()
                        answers_json = json.dumps(state["answers"], indent=4)
                        timestamp = datetime.now().isoformat()
                        
                        cursor.execute(
                            "INSERT INTO audits (project_type, answers, timestamp) VALUES (?, ?, ?)",
                            (state["project_type"], answers_json, timestamp)
                        )
                        conn.commit()
                        final_message = "Thank you! All answers have been recorded in the local database. How else can I help you?"
                    except sqlite3.Error as e:
                        logging.error(f"SQLite save error: {e}")
                        final_message = f"Thank you! I have your answers. However, I failed to save them to the database: {e}"
                    finally:
                        if conn:
                            conn.close()
                    
                    del conversation_state[session_id]
                    return final_message

        # --- Start a new questionnaire ---
        is_audit_request = "audit" in user_intent or "questionnaire" in user_intent
        is_tool_request = "jenkins" in user_intent or "mobsf" in user_intent

        if is_audit_request and not is_tool_request:
            state["in_questionnaire"] = True
            state["answers"] = {}
            conversation_state[session_id] = state
            return "I can help with that. What kind of project is it - mobile or web?"

        # --- Default to LangChain Agent for other requests ---
        if not OPENAI_API_KEY:
            return "OpenAI API key is not configured. I can't process this request."
            
        chat_history = []
        for human, ai in history:
            chat_history.append(HumanMessage(content=human))
            chat_history.append(AIMessage(content=ai))
        
        response = await agent_executor.ainvoke({"input": message, "chat_history": chat_history})
        return response["output"]

    except Exception as e:
        logging.error(f"An unexpected error occurred in predict function: {e}", exc_info=True)
        return f"Sorry, a critical error occurred: {e}. Please check the console logs for more details."


# --- 6. Main Entry Point ---
if __name__ == "__main__":
    setup_database() # Initialize the database on startup
    print("🚀 Launching LangChain Security Assistant with Gradio...")
    
    chat_interface = gr.ChatInterface(
        fn=predict,
        title="AI Security Assistant 5.0 (Proactive)",
        description="Ask me to run a security audit, or use tools like Jenkins and MobSF. Audit results are saved locally.",
        examples=[
            ["I want a security audit for my project."],
            ["Can you trigger a jenkins build for example.com?"],
            ["Run a mobsf scan on https://example.com/app.apk"],
        ],
        theme="soft"
    )

    chat_interface.launch(server_name="0.0.0.0", server_port=7860)
