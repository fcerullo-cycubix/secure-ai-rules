import { Rule } from "../components/SecureAIDirectory";

const accessControl: Rule = {
  id: "access-control",
  title: "Model & Tool Access Control",
  summary: "Enforce per-user authZ, rate limits, quotas, and tenant isolation across models and tools.",
  body:
    `- Gate model usage by user role and data classification.
- Enforce per-user and per-tenant quotas to prevent abuse/billing spikes.
- Separate inference and admin planes; protect prompt libraries and eval sets.
- Require approvals for high-risk tools (payments, email, code exec).`,
  tags: ["IAM", "Ops"],
};

export default accessControl;
