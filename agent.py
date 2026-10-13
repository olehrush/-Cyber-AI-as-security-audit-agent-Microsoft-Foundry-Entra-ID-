"""Entra audit agent: Claude (Foundry) decides when to query Graph (read-only)."""
import os
import json
from dotenv import load_dotenv
from anthropic import AnthropicFoundry
import graph_client as gc

load_dotenv()

client = AnthropicFoundry(
    api_key=os.environ["ANTHROPIC_FOUNDRY_API_KEY"],
    resource=os.environ["ANTHROPIC_FOUNDRY_RESOURCE"],
)

# Map tool names the model can call -> local read-only functions
TOOL_FUNCS = {
    "list_global_admins": gc.list_global_admins,
    "list_guest_users": gc.list_guest_users,
    "list_conditional_access_policies": gc.list_conditional_access_policies,
    "list_service_principals": gc.list_service_principals,
    "list_directory_roles": gc.list_directory_roles,
    "list_privileged_owners": gc.list_privileged_owners,
}

TOOLS = [
    {"name": n, "description": f"Read-only Entra ID query: {n}.",
     "input_schema": {"type": "object", "properties": {}}}
    for n in TOOL_FUNCS
]

SYSTEM = (
    "You are a Microsoft Entra ID security auditor for a lab tenant. "
    "Use the read-only tools to fetch live data before answering; never guess. Always run list_privileged_owners to detect ownership-based privilege-escalation paths (a user owning a service principal or group that holds a privileged role). "
    "When you find an issue, state the Finding, Severity, why it is a risk, and the fix."
)


def run(question: str) -> str:
    messages = [{"role": "user", "content": question}]
    while True:
        resp = client.messages.create(
            model="claude-opus-5-5", max_tokens=4000,
            system=SYSTEM, tools=TOOLS, messages=messages,
        )
        if resp.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": resp.content})
            results = []
            for block in resp.content:
                if block.type == "tool_use":
                    try:
                        data = TOOL_FUNCS[block.name]()
                    except Exception as e:
                        data = {"error": str(e)}
                    results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(data, default=str)[:20000],
                    })
            messages.append({"role": "user", "content": results})
            continue
        return "".join(b.text for b in resp.content if b.type == "text")


if __name__ == "__main__":
    print(run("Audit this tenant. Report Global Admins, risky privileged accounts, AND any ownership-based privilege-escalation paths where a non-admin user owns a service principal or group that holds a privileged directory role. For each flaw give Finding, Severity, why it matters, and the fix."))
