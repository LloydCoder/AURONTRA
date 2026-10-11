import Link from "next/link";

const capabilities = [
  { number: "01", title: "Operational resilience", detail: "Review service health, telemetry freshness, and evidence-backed risk signals." },
  { number: "02", title: "Governed response", detail: "Track remediation intent, approval state, and independently verified outcomes." },
  { number: "03", title: "Tenant-safe operations", detail: "Keep organization boundaries and access policy explicit throughout the workflow." },
];

export default function HomePage() {
  return (
    <main className="shell">
      <header className="topbar">
        <Link href="/" className="brand" aria-label="Aurontra home"><span className="brand-mark">A</span><span>AURONTRA</span></Link>
        <span className="environment"><i /> CONTROL PLANE · PREVIEW</span>
      </header>
      <section className="hero">
        <p className="eyebrow">RESILIENCE, WITH EVIDENCE</p>
        <h1>Know what is happening.<br /><em>Prove what happened next.</em></h1>
        <p className="lede">A governed operations workspace for teams responsible for reliable, secure systems. Decisions stay reviewable. Consequential actions stay under explicit policy and approval.</p>
        <div className="actions"><Link className="primary" href="/dashboard">Open console <span aria-hidden="true">↗</span></Link><span className="quiet">Preview interface · No live actions enabled</span></div>
      </section>
      <section className="capabilities" aria-label="Platform capabilities">
        {capabilities.map((item) => <article className="capability" key={item.number}><span className="number">{item.number}</span><h2>{item.title}</h2><p>{item.detail}</p></article>)}
      </section>
      <footer><span>© Aurontra · Tinlance ecosystem</span><span>Execution authority remains with the Agent Platform.</span></footer>
    </main>
  );
}
