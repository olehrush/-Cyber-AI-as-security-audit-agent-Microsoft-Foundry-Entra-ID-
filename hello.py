import os
from dotenv import load_dotenv
from anthropic import AnthropicFoundry

load_dotenv()

client = AnthropicFoundry(
    api_key=os.environ["ANTHROPIC_FOUNDRY_API_KEY"],
    resource=os.environ["ANTHROPIC_FOUNDRY_RESOURCE"],
)

msg = client.messages.create(
    model="claude-opus-5-5",
    max_tokens=512,
    system="You are a concise Microsoft Entra ID security auditor.",
    messages=[{"role": "user", "content": "In one sentence, why is legacy authentication a risk?"}],
)

text = "".join(block.text for block in msg.content if block.type == "text")
print(text)
