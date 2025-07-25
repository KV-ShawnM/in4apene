import os
from slack_bolt.adapter.fastapi.async_handler import AsyncSlackRequestHandler
from slack_bolt.async_app import AsyncApp
from agent import agent

# slack_app = AsyncApp(token=os.getenv("SLACK_BOT_TOKEN"), signing_secret=os.getenv("SLACK_SIGNING_SECRET"))
slack_app = AsyncApp(token=os.getenv("SLACK_BOT_TOKEN"))
handler = AsyncSlackRequestHandler(slack_app)

@slack_app.message("")
async def handle_message(message, say):
    user_input = message['text']
    response = agent.run(user_input)
    await say(response)

async def slack_event_handler(request):
    return await handler.handle(request)
