from fastapi import FastAPI, Request
from slack.slack_events import slack_event_handler

from dotenv import load_dotenv
load_dotenv()


app = FastAPI()

@app.post("/slack/events")
async def slack_events(request: Request):
    return await slack_event_handler(request)
