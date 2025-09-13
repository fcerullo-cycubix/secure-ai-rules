import { Rule } from "../components/SecureAIDirectory";

const supplyChain: Rule = {
  id: "supply-chain",
  title: "Supply Chain & Dependency Safety",
  summary: "Pin versions, verify publishers, and sandbox third-party tool plugins.",
  body:
    `- Use lockfiles and "allowed list" of NPM packages; monitor for typosquats.
- Enable provenance/SLSA where possible; verify package signatures.
- Run \nnpx npm-audit\n and integrate Dependabot/Renovate with "security-first" policies.
- For tool plugins/agents, review permissions and network egress; run in restricted containers.`,
  tags: ["Supply Chain", "DevSecOps"],
};

export default supplyChain;
