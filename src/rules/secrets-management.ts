import { Rule } from "../components/SecureAIDirectory";

const secretsManagement: Rule = {
  id: "secrets-management",
  title: "Secrets & Credentials Hygiene",
  summary: "No secrets in prompts. No secrets in repos. Rotate, scope, and vault everything.",
  body:
    `Do:
- Store API keys in a secrets manager (e.g., cloud KMS/Secrets Manager).
- Use short-lived tokens and scoped service accounts for tools/functions.
- Never concatenate secrets into prompts; tools should receive them out-of-band.
- Add pre-commit and CI scanners for hardcoded secrets; block merges on hits.
- Rotate keys regularly and on any suspected leak.`,
  tags: ["Ops", "AppSec"],
};

export default secretsManagement;
