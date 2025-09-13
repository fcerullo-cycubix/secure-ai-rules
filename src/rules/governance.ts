import { Rule } from "../components/SecureAIDirectory";

const governance: Rule = {
  id: "governance",
  title: "Policy, Legal & Governance",
  summary: "Document acceptable use, data retention, provenance, human oversight, and user disclosures.",
  body:
    `- Maintain a public user notice (what models are used, data handling, user choices).
- Record legal bases for processing (GDPR/DPDPA etc.) and enable DSR flows.
- Track third-country transfers and subprocessors; sign DPAs.
- Define AI incident response criteria and playbooks.`,
  tags: ["Governance", "Compliance"],
};

export default governance;
