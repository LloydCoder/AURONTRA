import Link from "next/link";

const checks = [
  { name: "Identity and tenant context", state: "Required", tone: "amber", detail: "Configure the approved identity provider before connecting live data." },
  { name: "Threat containment", state: "Disabled", tone: "neutral", detail: "Containment remains fail-closed until the Platform and independent verifier are accepted." },
  { name: "Production data plane", state: "Disabled", tone: "neutral", detail: "This preview does not fetch, mutate, or fabricate customer operational data." },
];
const steps = ["Connect an approved identity provider", "Verify tenant isolation and authorization", "Validate versioned Platform contracts in a controlled sandbox", "Complete operational and release acceptance"];

export default function DashboardPage() {
  return <main className="shell">
    <header className="topbar"><Link href="/" className="brand"><span className="brand-mark">A</span><span>AURONTRA</span></Link><Link href="/" className="quiet">← Back to overview</Link></header>
    <section className="hero dashboard-hero">
      <p className="eyebrow">OPERATIONS WORKSPACE / PREVIEW</p><h1>Evidence before<br/><em>action.</em></h1>
      <p className="lede">This is a non-production console shell. Live operational records are intentionally not displayed until authenticated API access and tenant-scoped integration have been configured and verified.</p>
    </section>
    <section aria-labelledby="readiness-title">
      <div className="section-heading"><h2 id="readiness-title">Integration readiness</h2><span className="quiet">NO LIVE CONNECTION</span></div>
      <div className="readiness-list">{checks.map((check)=><article key={check.name} className="capability readiness-item"><h3>{check.name}</h3><span className={`state ${check.tone}`}>{check.state}</span><p>{check.detail}</p></article>)}</div>
    </section>
    <section className="release-path"><h2>Release path</h2><ol className="steps">{steps.map((step,i)=><li key={step}><span>{String(i+1).padStart(2,"0")}</span>{step}</li>)}</ol></section>
    <footer><span>Preview only · No customer data or actions</span><span>Platform remains the sole execution authority.</span></footer>
  </main>;
}
