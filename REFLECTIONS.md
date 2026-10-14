# Reflections: building an AI agent for identity security

**Project:** AI-driven Entra ID misconfiguration auditor (Claude via Microsoft Foundry + Microsoft Graph), tested against the EntraGoat lab.

## What worked
- A tool-calling loop where Claude decides *when* to query Graph, with strictly read-only tools, produced a clear, prioritised audit — and in the end the agent autonomously found the EntraGoat Scenario 1 escalation path (a non-admin user owning a service principal that holds Privileged Authentication Administrator).
- Separating "brain" (Foundry/Claude in the Cybersteps tenant) from "target" (Graph in the Pearson lab tenant) kept the design clean: the two tenants never talk directly; a local Python bridge talks to each independently.However, in order to test something you need to modify the scripts, ideally (and there was a longer workaround to implement this) would be ability to chat directly with Agent and get security scan results via typical prompt and direct communications with Agent.

## Difficulties
0. **Navigating Entra Goat** I only managed to solve 1 Entra Goat scenario as implementation was a bit of challenging and confusing. It was not very clear how to solve them (via web which was buggy and not working all the time or via Terminal). There was not much info about this part, would be nice to include more walk-through about this project part.
1. **A missing tool means a missing vulnerability.** The first runs had no ownership tool, so the agent reported only generic hygiene issues and completely missed the real attack path. An identity auditor is only as good as the questions (tools) it can ask — the model cannot find what it cannot query.
2. **Silent false negatives are the dangerous failure mode.** My first ownership tool walked roles→members→owners and returned "no escalation paths" — which read like a clean result but was a bug. In security, a confident empty result is worse than an error. Rebuilding it to walk servicePrincipal/group → memberOf + owners (the direction that worked manually) fixed it. Lesson: validate detection logic against a known-true finding before trusting a "pass".
3. **Permissions and consent shape what's possible.** Read-only auditing needs Directory.Read.All/Application.Read.All with admin consent; setting up the lab needed Directory.AccessAsUser.All (a 403 on password resets until that scope was consented). Least privilege for the auditor vs. the privilege needed to run the scenario are two different problems.
4. **The agent knows its own blind spots — if told to report them.** The final report honestly flagged a truncated service-principal list and the lack of tools for other privileged roles / MFA state. Teaching the model to state coverage gaps is as valuable as the findings themselves.


