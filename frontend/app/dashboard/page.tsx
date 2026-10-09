"use client";
import { useState, useEffect, useCallback } from "react";

// ── Types ──────────────────────────────────────────────────────────────
type Device = {
  id: string;
  name: string;
  resilience_score: number;
  resilience_status: "healthy" | "warning" | "critical" | "unknown";
  last_telemetry?: Record<string, number>;
};

type Ticket = {
  id: string;
  title: string;
  status: string;
  priority: string;
  ai_resolved: boolean;
  escalated: boolean;
  reporter_email: string;
  source: string;
};

type AgentEvent = {
  id: string;
  type: "resolve" | "block" | "heal" | "predict" | "score";
  label: string;
  message: string;
  time: string;
  device?: string;
};

type Stats = {
  tickets_resolved: number;
  threats_blocked: number;
  devices_healthy: number;
  avg_resilience: number;
};

// ── Palette tokens ─────────────────────────────────────────────────────
const C = {
  navy:      "#050D1A",
  navyMid:   "#0A1628",
  navyCard:  "#0D1F3C",
  navyLift:  "#112244",
  teal:      "#00C9B1",
  tealDim:   "#007A6B",
  tealGlow:  "rgba(0,201,177,0.12)",
  danger:    "#FF4B6E",
  gold:      "#FFB547",
  green:     "#28CA41",
  white:     "#FFFFFF",
  offWhite:  "#E8F4F8",
  muted:     "#5A7A94",
  border:    "rgba(0,201,177,0.1)",
};

// ── Seed data ──────────────────────────────────────────────────────────
const SEED_DEVICES: Device[] = [
  { id: "srv-001", name: "prod-server-01",  resilience_score: 87, resilience_status: "healthy" },
  { id: "srv-002", name: "prod-db-01",      resilience_score: 62, resilience_status: "warning" },
  { id: "srv-003", name: "api-gateway-01",  resilience_score: 94, resilience_status: "healthy" },
  { id: "srv-004", name: "worker-node-02",  resilience_score: 38, resilience_status: "critical" },
  { id: "srv-005", name: "backup-srv-01",   resilience_score: 91, resilience_status: "healthy" },
];

const SEED_TICKETS: Ticket[] = [
  { id: "tkt-a1b2", title: "VPN disconnecting every 10 min",   status: "resolved",  priority: "medium", ai_resolved: true,  escalated: false, reporter_email: "james@corp.com",  source: "email" },
  { id: "tkt-c3d4", title: "Can't access company email",        status: "resolved",  priority: "high",   ai_resolved: true,  escalated: false, reporter_email: "sarah@corp.com",  source: "webhook" },
  { id: "tkt-e5f6", title: "Production DB high memory usage",   status: "escalated", priority: "critical",ai_resolved: false, escalated: true,  reporter_email: "ops@corp.com",    source: "agent" },
  { id: "tkt-g7h8", title: "Slack not loading on macOS",        status: "open",      priority: "low",    ai_resolved: false, escalated: false, reporter_email: "dev@corp.com",    source: "manual" },
  { id: "tkt-i9j0", title: "Password reset for new hire",       status: "resolved",  priority: "medium", ai_resolved: true,  escalated: false, reporter_email: "hr@corp.com",     source: "email" },
];

const AGENT_LOG_POOL: Omit<AgentEvent, "id" | "time">[] = [
  { type: "resolve", label: "RESOLVED", message: "Ticket #tkt-a1b2 — VPN timeout resolved via config push", device: "prod-server-01" },
  { type: "block",   label: "BLOCKED",  message: "Merlin QUIC C2 beacon — 185.220.101.x — Z=14.76 blocked", device: "api-gateway-01" },
  { type: "heal",    label: "HEALED",   message: "Disk cleanup on prod-db-01 — 3.2GB freed", device: "prod-db-01" },
  { type: "predict", label: "FORECAST", message: "Memory pressure rising on worker-node-02 — intervention in 4h", device: "worker-node-02" },
  { type: "resolve", label: "RESOLVED", message: "Ticket #tkt-i9j0 — Password reset applied for new hire", device: undefined },
  { type: "block",   label: "BLOCKED",  message: "Cobalt Strike beacon — 10.0.2.15 — lateral movement blocked", device: "prod-server-01" },
  { type: "heal",    label: "HEALED",   message: "TLS cert auto-renewed — api.resilientai.tinlance.com", device: "api-gateway-01" },
  { type: "score",   label: "SCORED",   message: "Resilience score updated — prod-server-01: 87 (healthy)", device: "prod-server-01" },
  { type: "predict", label: "FORECAST", message: "Disk growth trend on prod-db-01 — will fill in ~18hr", device: "prod-db-01" },
  { type: "resolve", label: "RESOLVED", message: "Ticket #tkt-c3d4 — Outlook auth token refreshed", device: undefined },
];

// ── Helpers ────────────────────────────────────────────────────────────
function nowTime() {
  const d = new Date();
  return `${String(d.getHours()).padStart(2,"0")}:${String(d.getMinutes()).padStart(2,"0")}:${String(d.getSeconds()).padStart(2,"0")}`;
}

function scoreColor(score: number) {
  if (score >= 80) return C.teal;
  if (score >= 60) return C.gold;
  return C.danger;
}

function statusDot(status: string) {
  if (status === "healthy")  return C.teal;
  if (status === "warning")  return C.gold;
  if (status === "critical") return C.danger;
  return C.muted;
}

function badgeColors(type: AgentEvent["type"]) {
  return {
    resolve: { bg: "rgba(0,201,177,0.15)",  color: C.teal },
    block:   { bg: "rgba(255,75,110,0.15)", color: C.danger },
    heal:    { bg: "rgba(40,202,65,0.15)",  color: C.green },
    predict: { bg: "rgba(255,181,71,0.15)", color: C.gold },
    score:   { bg: "rgba(90,122,148,0.2)",  color: C.muted },
  }[type];
}

function priorityColor(p: string) {
  if (p === "critical") return C.danger;
  if (p === "high")     return "#FF8C42";
  if (p === "medium")   return C.gold;
  return C.muted;
}

// ── Components ─────────────────────────────────────────────────────────
function StatCard({ value, label, color = C.teal, sub }: { value: string | number; label: string; color?: string; sub?: string }) {
  return (
    <div style={{
      background: C.navyCard,
      border: `1px solid ${C.border}`,
      borderRadius: 14,
      padding: "1.25rem 1.5rem",
      flex: 1,
    }}>
      <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "2.2rem", fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: "0.8rem", color: C.muted, marginTop: "0.35rem" }}>{label}</div>
      {sub && <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem", color: C.tealDim, marginTop: "0.25rem" }}>{sub}</div>}
    </div>
  );
}

function ResilienceGauge({ score, name, status }: { score: number; name: string; status: string }) {
  const color = scoreColor(score);
  const pct = score;
  const r = 28, cx = 36, cy = 36;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;

  return (
    <div style={{
      background: C.navyCard,
      border: `1px solid ${C.border}`,
      borderRadius: 12,
      padding: "1rem",
      display: "flex",
      alignItems: "center",
      gap: "0.85rem",
      cursor: "default",
      transition: "border-color 0.2s",
    }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = color)}
      onMouseLeave={e => (e.currentTarget.style.borderColor = C.border)}
    >
      <svg width={72} height={72} style={{ flexShrink: 0 }}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.navyLift} strokeWidth={6} />
        <circle
          cx={cx} cy={cy} r={r} fill="none"
          stroke={color} strokeWidth={6}
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition: "stroke-dasharray 1s ease" }}
        />
        <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="middle"
          style={{ fill: color, fontSize: 14, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif" }}>
          {score}
        </text>
      </svg>
      <div>
        <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "0.875rem", fontWeight: 600, color: C.white }}>{name}</div>
        <div style={{ display: "flex", alignItems: "center", gap: 5, marginTop: 4 }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: statusDot(status), display: "inline-block" }} />
          <span style={{ fontSize: "0.72rem", color: C.muted, textTransform: "capitalize" }}>{status}</span>
        </div>
      </div>
    </div>
  );
}

function TicketCard({ ticket }: { ticket: Ticket }) {
  const statusColor = ticket.status === "resolved" ? C.teal : ticket.status === "escalated" ? C.danger : C.muted;
  return (
    <div style={{
      background: C.navyCard,
      border: `1px solid ${C.border}`,
      borderRadius: 10,
      padding: "0.85rem 1rem",
      display: "flex",
      alignItems: "center",
      gap: "0.85rem",
    }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "0.875rem", fontWeight: 600, color: C.white, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {ticket.title}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginTop: 4 }}>
          <span style={{ fontSize: "0.7rem", color: C.muted }}>{ticket.reporter_email}</span>
          <span style={{ width: 3, height: 3, borderRadius: "50%", background: C.muted, display: "inline-block" }} />
          <span style={{ fontSize: "0.7rem", color: priorityColor(ticket.priority) }}>{ticket.priority}</span>
        </div>
      </div>
      <div style={{ flexShrink: 0, display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
        <span style={{
          padding: "0.15rem 0.55rem",
          borderRadius: 4,
          background: ticket.ai_resolved ? "rgba(0,201,177,0.12)" : "rgba(90,122,148,0.15)",
          color: ticket.ai_resolved ? C.teal : C.muted,
          fontSize: "0.65rem", fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
        }}>
          {ticket.ai_resolved ? "AI" : ticket.escalated ? "ESC" : "OPEN"}
        </span>
        <span style={{ fontSize: "0.65rem", color: statusColor, fontFamily: "'JetBrains Mono', monospace" }}>
          {ticket.status.toUpperCase()}
        </span>
      </div>
    </div>
  );
}

function ThreatFeedPanel({ events }: { events: AgentEvent[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
      {events.slice(0, 6).filter(e => e.type === "block" || e.type === "predict").map(ev => {
        const bc = badgeColors(ev.type);
        return (
          <div key={ev.id} style={{
            display: "flex",
            alignItems: "center",
            gap: "0.6rem",
            padding: "0.4rem 0.6rem",
            background: C.navyLift,
            borderRadius: 6,
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "0.7rem",
          }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: bc?.color, flexShrink: 0, animation: ev.type === "block" ? "pulse 1.5s infinite" : undefined }} />
            <span style={{ color: C.muted, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{ev.message}</span>
            <span style={{ padding: "0.1rem 0.4rem", borderRadius: 3, background: bc?.bg, color: bc?.color, fontSize: "0.6rem", fontWeight: 700, flexShrink: 0 }}>{ev.label}</span>
          </div>
        );
      })}
    </div>
  );
}

// ── Main Dashboard ─────────────────────────────────────────────────────
export default function Dashboard() {
  const [devices]        = useState<Device[]>(SEED_DEVICES);
  const [tickets]        = useState<Ticket[]>(SEED_TICKETS);
  const [agentLog, setAgentLog] = useState<AgentEvent[]>([]);
  const [activeTab, setActiveTab] = useState<"overview" | "tickets" | "devices" | "threats">("overview");
  const [stats, setStats] = useState<Stats>({
    tickets_resolved: 0,
    threats_blocked:  0,
    devices_healthy:  0,
    avg_resilience:   0,
  });

  // Compute stats from seed data
  useEffect(() => {
    setStats({
      tickets_resolved: tickets.filter(t => t.ai_resolved).length,
      threats_blocked:  agentLog.filter(e => e.type === "block").length,
      devices_healthy:  devices.filter(d => d.resilience_status === "healthy").length,
      avg_resilience:   Math.round(devices.reduce((s, d) => s + d.resilience_score, 0) / devices.length),
    });
  }, [tickets, devices, agentLog]);

  // Live agent event stream
  let logIdx = 0;
  useEffect(() => {
    const tick = () => {
      const entry = AGENT_LOG_POOL[logIdx % AGENT_LOG_POOL.length];
      logIdx++;
      const event: AgentEvent = {
        ...entry,
        id: `${Date.now()}-${Math.random()}`,
        time: nowTime(),
      };
      setAgentLog(prev => [event, ...prev].slice(0, 20));
    };
    // Seed first 4 events immediately
    for (let i = 0; i < 4; i++) setTimeout(tick, i * 150);
    const interval = setInterval(tick, 3200);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { key: "overview", label: "Overview" },
    { key: "devices",  label: "Devices" },
    { key: "tickets",  label: "Tickets" },
    { key: "threats",  label: "Threats" },
  ] as const;

  return (
    <div style={{ minHeight: "100vh", background: C.navy, color: C.offWhite, fontFamily: "'Inter', sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #050D1A; }
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(0.8)} }
        @keyframes slideIn { from{opacity:0;transform:translateX(-6px)} to{opacity:1;transform:translateX(0)} }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #050D1A; }
        ::-webkit-scrollbar-thumb { background: #112244; border-radius: 2px; }
      `}</style>

      {/* Top nav */}
      <nav style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 100,
        height: 60,
        background: "rgba(5,13,26,0.9)",
        backdropFilter: "blur(16px)",
        borderBottom: `1px solid ${C.border}`,
        display: "flex", alignItems: "center",
        padding: "0 1.5rem",
        gap: "2rem",
      }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, fontSize: "1rem", color: C.white }}>
          <div style={{ width: 28, height: 28, background: C.teal, borderRadius: 7, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M8 1L1.5 4v4c0 3.3 2.7 6.3 6.5 7 3.8-.7 6.5-3.7 6.5-7V4L8 1z" fill="#050D1A"/>
              <path d="M5 8l2 2 4-4" stroke="#00C9B1" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          ResilientAI
        </div>

        {/* Nav tabs */}
        <div style={{ display: "flex", gap: "0.25rem" }}>
          {navItems.map(item => (
            <button
              key={item.key}
              onClick={() => setActiveTab(item.key)}
              style={{
                padding: "0.4rem 0.9rem",
                borderRadius: 6,
                border: "none",
                background: activeTab === item.key ? C.tealGlow : "transparent",
                color: activeTab === item.key ? C.teal : C.muted,
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: "0.825rem", fontWeight: 500,
                cursor: "pointer",
                transition: "all 0.15s",
                borderBottom: activeTab === item.key ? `2px solid ${C.teal}` : "2px solid transparent",
              }}
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Status indicator */}
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6, fontFamily: "'JetBrains Mono', monospace", fontSize: "0.7rem", color: C.teal }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.teal, animation: "pulse 1.5s infinite" }} />
          LIVE · ThreatFade active
        </div>
      </nav>

      {/* Main layout */}
      <div style={{ paddingTop: 60, display: "grid", gridTemplateColumns: "1fr 340px", minHeight: "calc(100vh - 60px)" }}>

        {/* Left content */}
        <div style={{ padding: "1.5rem", overflowY: "auto", borderRight: `1px solid ${C.border}` }}>

          {/* Stat strip */}
          <div style={{ display: "flex", gap: "1rem", marginBottom: "1.5rem" }}>
            <StatCard value={stats.tickets_resolved} label="Tickets auto-resolved" color={C.teal} sub="// ai agent" />
            <StatCard value={stats.threats_blocked}  label="Threats blocked"       color={C.danger} sub="// threatfade" />
            <StatCard value={`${stats.avg_resilience}%`} label="Avg resilience score" color={scoreColor(stats.avg_resilience)} sub="// all devices" />
            <StatCard value={`${stats.devices_healthy}/${devices.length}`} label="Devices healthy" color={C.green} sub="// live" />
          </div>

          {/* Tab content */}
          {activeTab === "overview" && (
            <>
              <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "0.7rem", fontWeight: 600, color: C.teal, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "0.75rem" }}>
                Device Resilience
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "1.5rem" }}>
                {devices.map(d => <ResilienceGauge key={d.id} score={d.resilience_score} name={d.name} status={d.resilience_status} />)}
              </div>

              <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "0.7rem", fontWeight: 600, color: C.teal, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "0.75rem" }}>
                Recent Tickets
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
                {tickets.slice(0, 4).map(t => <TicketCard key={t.id} ticket={t} />)}
              </div>
            </>
          )}

          {activeTab === "devices" && (
            <>
              <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "0.7rem", fontWeight: 600, color: C.teal, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "0.75rem" }}>
                All Devices — Resilience Map
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                {devices.map(d => (
                  <div key={d.id} style={{ background: C.navyCard, border: `1px solid ${C.border}`, borderRadius: 12, padding: "1rem 1.25rem", display: "flex", alignItems: "center", gap: "1rem" }}>
                    <ResilienceGauge score={d.resilience_score} name={d.name} status={d.resilience_status} />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                        {d.last_telemetry && Object.entries(d.last_telemetry).map(([k, v]) => (
                          <div key={k} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.7rem" }}>
                            <span style={{ color: C.muted }}>{k.replace("_percent", "")}:</span>{" "}
                            <span style={{ color: v > 80 ? C.danger : C.offWhite }}>{v}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}

          {activeTab === "tickets" && (
            <>
              <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "0.7rem", fontWeight: 600, color: C.teal, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "0.75rem" }}>
                All Tickets
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
                {tickets.map(t => <TicketCard key={t.id} ticket={t} />)}
              </div>
              <div style={{ marginTop: "1rem", padding: "0.75rem 1rem", background: C.navyCard, border: `1px solid ${C.border}`, borderRadius: 10, fontFamily: "'JetBrains Mono', monospace", fontSize: "0.72rem", color: C.muted }}>
                AI resolution rate: <span style={{ color: C.teal, fontWeight: 600 }}>{Math.round(tickets.filter(t => t.ai_resolved).length / tickets.length * 100)}%</span>
                {" · "}Escalation rate: <span style={{ color: C.danger }}>{Math.round(tickets.filter(t => t.escalated).length / tickets.length * 100)}%</span>
              </div>
            </>
          )}

          {activeTab === "threats" && (
            <>
              <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "0.7rem", fontWeight: 600, color: C.teal, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "0.75rem" }}>
                Threat Feed — ThreatFade v0.2.0
              </div>
              <ThreatFeedPanel events={agentLog} />
              <div style={{ marginTop: "1rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                <div style={{ background: C.navyCard, border: `1px solid ${C.border}`, borderRadius: 10, padding: "1rem" }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem", color: C.muted, marginBottom: 4 }}>// detection engine</div>
                  <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "1.4rem", fontWeight: 700, color: C.teal }}>14.76</div>
                  <div style={{ fontSize: "0.75rem", color: C.muted }}>Z-score — Merlin QUIC</div>
                </div>
                <div style={{ background: C.navyCard, border: `1px solid ${C.border}`, borderRadius: 10, padding: "1rem" }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem", color: C.muted, marginBottom: 4 }}>// false positive rate</div>
                  <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "1.4rem", fontWeight: 700, color: C.green }}>0%</div>
                  <div style={{ fontSize: "0.75rem", color: C.muted }}>490K+ packets validated</div>
                </div>
              </div>
            </>
          )}
        </div>

        {/* Right rail — live agent feed (signature element) */}
        <div style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem", overflowY: "auto" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "'JetBrains Mono', monospace", fontSize: "0.7rem", color: C.teal }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.teal, animation: "pulse 1.5s infinite" }} />
            autonomous agent · live
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.45rem" }}>
            {agentLog.map((ev, i) => {
              const bc = badgeColors(ev.type);
              return (
                <div
                  key={ev.id}
                  style={{
                    background: C.navyCard,
                    border: `1px solid ${C.border}`,
                    borderRadius: 8,
                    padding: "0.55rem 0.75rem",
                    animation: i === 0 ? "slideIn 0.3s ease" : undefined,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: 4 }}>
                    <span style={{
                      padding: "0.1rem 0.45rem",
                      borderRadius: 3,
                      background: bc?.bg,
                      color: bc?.color,
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: "0.6rem", fontWeight: 700,
                    }}>{ev.label}</span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.62rem", color: C.muted, marginLeft: "auto" }}>{ev.time}</span>
                  </div>
                  <div style={{ fontSize: "0.75rem", color: C.offWhite, lineHeight: 1.4 }}>{ev.message}</div>
                  {ev.device && (
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.62rem", color: C.tealDim, marginTop: 3 }}>
                      // {ev.device}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Self-healing playbooks quick-trigger */}
          <div style={{ marginTop: "auto", borderTop: `1px solid ${C.border}`, paddingTop: "1rem" }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem", color: C.muted, marginBottom: "0.6rem" }}>// quick trigger playbooks</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.4rem" }}>
              {["disk_full", "service_restart", "cert_expiry", "high_cpu"].map(name => (
                <button
                  key={name}
                  style={{
                    padding: "0.45rem 0.5rem",
                    background: "transparent",
                    border: `1px solid ${C.border}`,
                    borderRadius: 6,
                    color: C.muted,
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: "0.62rem",
                    cursor: "pointer",
                    textAlign: "left",
                    transition: "all 0.15s",
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = C.teal; e.currentTarget.style.color = C.teal; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.muted; }}
                  onClick={() => {
                    const event: AgentEvent = {
                      id: `${Date.now()}`,
                      type: "heal",
                      label: "TRIGGERED",
                      message: `Playbook ${name} manually triggered`,
                      time: nowTime(),
                    };
                    setAgentLog(prev => [event, ...prev].slice(0, 20));
                  }}
                >
                  ▸ {name.replace("_", " ")}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
