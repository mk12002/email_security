import asyncio
from email_security.src.action_layer.graph_client import GraphActionBot
from email_security.src.configs.settings import settings
import logging

logging.basicConfig(level=logging.DEBUG)

def test_graph_bot():
    bot = GraphActionBot()
    print("Is configured?", bot.is_configured())
    token = bot._get_token()
    if token:
        print("Successfully acquired token!")
        # Let's try to resolve a fake message id to see if we get a 403 or 404
        status, resp = bot._graph_request("GET", f"/users/admin@domain.com/messages?$filter=internetMessageId eq 'fake-id'")
        print(f"Test query - Status: {status}, Response: {resp}")
    else:
        print("Failed to acquire token.")

if __name__ == "__main__":
    test_graph_bot()
