import React, { useEffect, useMemo, useState } from "react";
import "./App.css";

const demoPcaps = [
  ["Basic Traffic", "TCP/UDP sample", "/demo-pcaps/basic-traffic.pcap"],
  ["Mixed TCP/UDP", "Mixed protocol traffic", "/demo-pcaps/mixed-tcp-udp.pcap"],
  ["Application Classification", "Application/SNI detection", "/demo-pcaps/application-classification.pcap"],
  ["Blocking Demo", "Blocking rules demo", "/demo-pcaps/blocking-demo.pcap"],
];

const emptyStats = {
  totalPackets: 0, totalBytes: 0, forwardedPackets: 0, droppedPackets: 0,
  tcpPackets: 0, udpPackets: 0, otherPackets: 0, activeConnections: 0,
  lbReceived: 0, lbDispatched: 0, fpProcessed: 0, fpForwarded: 0,
  fpDropped: 0, applications: {}, trafficData: [],
  rules: { blockedIPs: 0, blockedApps: 0, blockedDomains: 0, blockedPorts: 0 },
};

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [outputFile, setOutputFile] = useState("");
  const [stats, setStats] = useState(emptyStats);
  const [connections, setConnections] = useState([]);
  const [rules, setRules] = useState({ ip: [], app: [], domain: [], port: [] });

  const loadInitialData = async () => {
    try {
      const [s, c, r] = await Promise.all([
        fetch("/stats.json").then((x) => x.json()),
        fetch("/connections.json").then((x) => x.json()),
        fetch("/api/rules").then((x) => x.json()).catch(() => ({ success: false })),
      ]);
      setStats({ ...emptyStats, ...s, applications: s.applications || {} });
      setConnections(c.connections || []);
      if (r.success) setRules(r.rules);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => { loadInitialData(); }, []);

  const analyzePCAP = async (file) => {
    if (!file) return;
    setAnalyzing(true);
    setError("");
    const formData = new FormData();
    formData.append("pcap", file);

    try {
      const response = await fetch("/api/analyze", { method: "POST", body: formData });
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || "Analysis failed");
      setStats({ ...emptyStats, ...data.stats, applications: data.stats.applications || {} });
      setConnections(data.connections || []);
      setOutputFile(data.outputFile || "");
    } catch (e) {
      setError(e.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const analyzeDemo = async (path, name) => {
    try {
      setError("");
      const response = await fetch(path);
      if (!response.ok) throw new Error("Could not load demo PCAP");
      const blob = await response.blob();
      const file = new File(
        [blob],
        `${name.replace(/\s+/g, "-").toLowerCase()}.pcap`,
        { type: "application/vnd.tcpdump.pcap" }
      );
      setSelectedFile(file);
      await analyzePCAP(file);
    } catch (e) {
      setError(e.message);
    }
  };

  const addRule = async () => {
    const type = window.prompt("Rule type: ip, domain, app, or port");
    if (!type) return;

    const normalized = type.trim().toLowerCase();

    if (!["ip", "domain", "app", "port"].includes(normalized)) {
      alert("Invalid type");
      return;
    }

    const value = window.prompt(`Enter ${normalized} to block:`);
    if (!value?.trim()) return;

    try {
      const response = await fetch("/api/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: normalized,
          value: value.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || "Failed to add rule");
      }

      setRules((p) => ({
        ...p,
        [normalized]: [...p[normalized], value.trim()],
      }));
    } catch (e) {
      alert(e.message);
    }
  };

  const deleteRule = async (type, value) => {
    if (!window.confirm(`Delete ${type} rule "${value}"?`)) return;

    try {
      const response = await fetch("/api/rules", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, value }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to delete rule");
      }

      setRules((p) => ({
        ...p,
        [type]: p[type].filter(
          (x) => x.toLowerCase() !== value.toLowerCase()
        ),
      }));
    } catch (e) {
      alert(e.message);
    }
  };

  const appRows = useMemo(() => {
    const entries = Object.entries(stats.applications || {});
    const total = entries.reduce((a, [, v]) => a + v, 0);

    return entries.map(([name, count]) => ({
      name,
      count,
      percent: total ? Math.round((count / total) * 100) : 0,
    }));
  }, [stats.applications]);

  const allRules = Object.entries(rules).flatMap(([type, values]) =>
    values.map((value) => ({ type, value }))
  );

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <div>
            <h1>PacketHunter</h1>
            <p>Deep Packet Inspection & Network Monitoring</p>
          </div>
        </div>

        <div className="status">
          <span className="status-dot" />
          DPI Engine Ready
        </div>
      </header>

      <main className="dashboard">

      {/* HERO */}
<section className="hero">
  <div className="eyebrow">PACKETHUNTER DPI</div>

  <h2>Network Traffic Analysis Dashboard</h2>

  <p>
    Upload a PCAP, run the C++ DPI engine, inspect applications and
    connections, apply blocking rules, and download the filtered
    traffic — all from one page.
  </p>

  <div className="upload-area">

    <div className="upload-main-row">
      <label className="upload-button">
        Choose PCAP
        <input
          type="file"
          accept=".pcap"
          onChange={(e) => {
            setSelectedFile(e.target.files?.[0] || null);
            setError("");
          }}
        />
      </label>

      <span className="file-name">
        {selectedFile?.name || "No file selected"}
      </span>

      <button
        className="primary-button"
        disabled={!selectedFile || analyzing}
        onClick={() => analyzePCAP(selectedFile)}
      >
        {analyzing ? "Analyzing..." : "Analyze PCAP"}
      </button>
    </div>

    {/* DEMO PCAPS */}
    <div className="hero-demo-section">
      <div className="hero-demo-title">
        <strong>Quick Demo PCAPs</strong>
        <span>Run a sample directly through the live backend.</span>
      </div>

      <div className="hero-demo-buttons">
        {demoPcaps.map(([name, desc, pcapPath]) => (
          <button
            key={pcapPath}
            className="demo-green-button"
            disabled={analyzing}
            title={desc}
            onClick={() => analyzeDemo(pcapPath, name)}
          >
            {analyzing ? "Analyzing..." : name}
          </button>
        ))}
      </div>
    </div>

    {outputFile && (
      <a
        className="secondary-button"
        href={`/api/download/${outputFile}`}
      >
        Download Filtered PCAP
      </a>
    )}

  </div>

  {error && <div className="error-message">{error}</div>}
</section>
        {/* BLOCKING RULES MOVED BEFORE ANALYSIS */}
        <section className="panel rules-panel">
          <div className="panel-title">
            <div>
              <span className="section-label">SECURITY</span>
              <h3>Blocking Rules</h3>
            </div>

            <button className="small-button" onClick={addRule}>
              + Add Rule
            </button>
          </div>

          <div className="rules">
            {allRules.length ? (
              allRules.map((r) => (
                <div
                  className="rule-row"
                  key={`${r.type}-${r.value}`}
                >
                  <span className="rule-type">
                    {r.type.toUpperCase()}
                  </span>

                  <strong>{r.value}</strong>

                  <span className="rule-status">BLOCK</span>

                  <button
                    className="delete-button"
                    onClick={() => deleteRule(r.type, r.value)}
                  >
                    Delete
                  </button>
                </div>
              ))
            ) : (
              <div className="empty-state">
                No active blocking rules. Click "+ Add Rule" to create one.
              </div>
            )}
          </div>
        </section>

        {/* STATS */}
        <section className="stats-grid">
          <div className="stat-card">
            <span>Total Packets</span>
            <strong>{stats.totalPackets.toLocaleString()}</strong>
            <small>
              {stats.totalBytes.toLocaleString()} bytes processed
            </small>
          </div>

          <div className="stat-card danger-stat">
            <span>Blocked / Dropped</span>
            <strong>{stats.droppedPackets.toLocaleString()}</strong>
            <small>
              {stats.rules?.blockedIPs || 0} IP ·{" "}
              {stats.rules?.blockedApps || 0} app rules matched
            </small>
          </div>

          <div className="stat-card">
            <span>Active Connections</span>
            <strong>{stats.activeConnections.toLocaleString()}</strong>
            <small>Tracked network flows</small>
          </div>

          <div className="stat-card">
            <span>Forwarded Packets</span>
            <strong>{stats.forwardedPackets.toLocaleString()}</strong>
            <small>Packets allowed by engine</small>
          </div>
        </section>

        {/* CONNECTIONS */}
        <section className="panel">
          <div className="panel-title">
            <div>
              <span className="section-label">NETWORK FLOWS</span>
              <h3>Connections</h3>
            </div>

            <span className="connection-count">
              {connections.length} flows
            </span>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>SNI / Domain</th>
                  <th>Application</th>
                  <th>Packets</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {connections.length ? (
                  connections.map((c, i) => (
                    <tr
                      key={`${c.source}-${c.destination}-${i}`}
                    >
                      <td>{c.source}</td>
                      <td>{c.destination}</td>
                      <td className="protocol">{c.protocol}</td>
                      <td>{c.sni || "-"}</td>
                      <td>{c.application}</td>
                      <td>{c.packets}</td>

                      <td>
                        <span
                          className={`pill ${
                            c.action === "BLOCK"
                              ? "blocked"
                              : "allowed"
                          }`}
                        >
                          {c.action || "ALLOW"}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="7" className="table-empty">
                      No connections yet. Analyze a PCAP above.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* APPLICATION CLASSIFICATION */}
        <section className="panel">
          <div className="panel-title">
            <div>
              <span className="section-label">CLASSIFICATION</span>
              <h3>Application Distribution</h3>
            </div>
          </div>

          <div className="application-list">
            {appRows.length ? (
              appRows.map((a) => (
                <div className="application-row" key={a.name}>
                  <div className="application-name">
                    <span className="app-dot" />
                    {a.name}
                  </div>

                  <div className="application-meter">
                    <div style={{ width: `${a.percent}%` }} />
                  </div>

                  <strong>{a.percent}%</strong>
                </div>
              ))
            ) : (
              <div className="empty-state">
                No applications classified yet.
              </div>
            )}
          </div>
        </section>

      </main>
    </div>
  );
}

export default App;