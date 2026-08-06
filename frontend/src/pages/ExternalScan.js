import { useState } from "react";
import axios from "axios";
import API_BASE from "../config";

export default function ExternalScan() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [activeFilter, setActiveFilter] = useState("All");

  const handleScan = async () => {
    if (!url) {
      alert("Please enter a website URL first!");
      return;
    }
    const sanitized = url.startsWith("http") ? url : `https://${url}`;
    setLoading(true);
    setResult(null);
    setActiveFilter("All");
    try {
      const res = await axios.post(
        `${API_BASE}/scan/external`,
        { url: sanitized },
        { headers: { "Content-Type": "application/json" } }
      );
      setResult(res.data);
    } catch (err) {
      console.error("External scan error:", err);
      alert("External scan failed. Please check your backend connection.");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") handleScan();
  };

  // ── Severity helpers ────────────────────────────────────────────────────────

  const SEV_CONFIG = {
    Critical: { bg: "bg-red-900/60",    text: "text-red-300",    border: "border-red-500",    dot: "bg-red-400"    },
    High:     { bg: "bg-orange-900/60", text: "text-orange-300", border: "border-orange-500", dot: "bg-orange-400" },
    Medium:   { bg: "bg-yellow-900/60", text: "text-yellow-300", border: "border-yellow-500", dot: "bg-yellow-400" },
    Low:      { bg: "bg-blue-900/60",   text: "text-blue-300",   border: "border-blue-500",   dot: "bg-blue-400"   },
    Info:     { bg: "bg-gray-800/60",   text: "text-gray-400",   border: "border-gray-500",   dot: "bg-gray-400"   },
  };
  const sev = (s) => SEV_CONFIG[s] || SEV_CONFIG.Info;

  // ── Vuln class → emoji ──────────────────────────────────────────────────────
  const VULN_ICONS = {
    "SQLi":            "🗄️",
    "XSS":             "⚡",
    "CMDi":            "💀",
    "SSRF":            "🌐",
    "SSTI":            "🔧",
    "Path Traversal":  "📂",
    "XXE":             "📋",
    "Open Redirect":   "↪️",
    "CORS":            "🔓",
    "Security Header": "🛡️",
    "HTTP Method":     "⚙️",
  };
  const vulnIcon = (vc) => VULN_ICONS[vc] || "🔍";

  // ── Score ring color ─────────────────────────────────────────────────────────
  const scoreColor = (s) => {
    if (s >= 80) return "text-emerald-400";
    if (s >= 60) return "text-yellow-400";
    if (s >= 40) return "text-orange-400";
    return "text-red-400";
  };

  const gradeColor = (g) => {
    if (!g) return "bg-gray-700";
    if (g === "A") return "bg-emerald-600";
    if (g === "B") return "bg-green-600";
    if (g === "C") return "bg-yellow-600";
    if (g === "D") return "bg-orange-600";
    return "bg-red-600";
  };

  // ── Counts per severity ──────────────────────────────────────────────────────
  const counts = result
    ? {
        Critical: (result.findings || []).filter((f) => f.severity === "Critical").length,
        High:     (result.findings || []).filter((f) => f.severity === "High").length,
        Medium:   (result.findings || []).filter((f) => f.severity === "Medium").length,
        Low:      (result.findings || []).filter((f) => f.severity === "Low").length,
      }
    : {};

  // ── Filter tabs ───────────────────────────────────────────────────────────
  const FILTER_TABS = ["All", "Critical", "High", "Medium", "Low"];
  const filteredFindings = result
    ? (result.findings || []).filter(
        (f) => activeFilter === "All" || f.severity === activeFilter
      )
    : [];

  // ── Vuln class group counts for sidebar ──────────────────────────────────
  const vulnGroups = result
    ? [...new Set((result.findings || []).map((f) => f.vuln_class || "Other"))].map((vc) => ({
        name: vc,
        count: (result.findings || []).filter((f) => (f.vuln_class || "Other") === vc).length,
      })).sort((a, b) => b.count - a.count)
    : [];

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0d1117] via-[#161b22] to-[#0d1117] text-gray-100 font-sans">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="border-b border-gray-800 bg-[#0d1117]/80 backdrop-blur-sm sticky top-0 z-20 px-8 py-4 flex items-center gap-4">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-lg">🌐</div>
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight">External Vulnerability Scan</h1>
          <p className="text-xs text-gray-500">Enterprise DAST · OWASP Top 10 · Security Headers · Method Fuzzing</p>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">

        {/* ── Scan Input ─────────────────────────────────────────────────── */}
        <div className="bg-gradient-to-r from-[#161b22] to-[#1c2129] border border-gray-700 rounded-2xl p-6 mb-8 shadow-2xl">
          <p className="text-sm text-gray-400 mb-3 font-medium">
            🎯 Enter the target URL to perform a full pentest-grade scan
          </p>
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500 text-sm select-none">https://</span>
              <input
                type="text"
                placeholder="example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={handleKeyDown}
                className="w-full pl-20 pr-4 py-3 bg-[#0d1117] border border-gray-700 rounded-xl text-gray-100 text-sm placeholder-gray-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all"
              />
            </div>
            <button
              onClick={handleScan}
              disabled={loading}
              className={`px-8 py-3 rounded-xl font-semibold text-sm transition-all ${
                loading
                  ? "bg-gray-700 text-gray-500 cursor-not-allowed"
                  : "bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-400 hover:to-blue-500 shadow-lg shadow-cyan-900/30 active:scale-95"
              }`}
            >
              {loading ? "Scanning…" : "Launch Scan →"}
            </button>
          </div>

          {/* Scan type badges */}
          <div className="flex flex-wrap gap-2 mt-4">
            {["SQLi", "XSS", "CMDi", "SSRF", "SSTI", "Path Traversal", "Open Redirect", "CORS", "Security Headers", "HTTP Methods", "JSON Injection"].map((t) => (
              <span key={t} className="px-2.5 py-0.5 text-xs font-medium bg-[#21262d] border border-gray-700 rounded-full text-gray-400">
                {t}
              </span>
            ))}
          </div>
        </div>

        {/* ── Loading animation ───────────────────────────────────────────── */}
        {loading && (
          <div className="bg-[#161b22] border border-cyan-900/50 rounded-2xl p-8 text-center mb-8">
            <div className="flex items-center justify-center gap-3 mb-4">
              <div className="w-3 h-3 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "0ms" }}></div>
              <div className="w-3 h-3 rounded-full bg-blue-400 animate-bounce" style={{ animationDelay: "150ms" }}></div>
              <div className="w-3 h-3 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "300ms" }}></div>
            </div>
            <p className="text-cyan-300 font-medium text-sm">Enterprise DAST engine running…</p>
            <p className="text-gray-500 text-xs mt-1">Crawling • Injecting • Confirming • Analyzing headers</p>
          </div>
        )}

        {/* ── Results ─────────────────────────────────────────────────────── */}
        {result && (
          <>
            {/* Score banner */}
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-6">
              {/* Big score */}
              <div className="col-span-2 bg-[#161b22] border border-gray-700 rounded-2xl p-5 flex items-center gap-4">
                <div className={`text-5xl font-black ${scoreColor(result.score?.score ?? 0)}`}>
                  {result.score?.score ?? 0}
                </div>
                <div>
                  <div className={`text-2xl font-bold px-3 py-1 rounded-lg text-white ${gradeColor(result.score?.grade)}`}>
                    {result.score?.grade ?? "?"}
                  </div>
                  <p className="text-xs text-gray-500 mt-1">Security Score</p>
                </div>
              </div>

              {/* Severity counts */}
              {["Critical", "High", "Medium", "Low"].map((s) => (
                <div key={s} className={`border rounded-xl p-4 ${SEV_CONFIG[s].bg} ${SEV_CONFIG[s].border}`}>
                  <div className={`text-3xl font-black ${SEV_CONFIG[s].text}`}>{counts[s] ?? 0}</div>
                  <div className={`text-xs font-semibold mt-1 ${SEV_CONFIG[s].text}`}>{s}</div>
                </div>
              ))}
            </div>

            {/* Main content: findings + sidebar */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">

              {/* Sidebar: vuln categories */}
              <div className="lg:col-span-1 space-y-3">
                <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-2">Vulnerability Types</h3>
                {vulnGroups.map(({ name, count }) => (
                  <div
                    key={name}
                    className="flex items-center justify-between bg-[#161b22] border border-gray-800 rounded-xl px-4 py-3 hover:border-cyan-700/50 transition cursor-pointer"
                    onClick={() => setActiveFilter("All")}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-base">{vulnIcon(name)}</span>
                      <span className="text-sm text-gray-300 font-medium">{name}</span>
                    </div>
                    <span className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded-full font-mono">{count}</span>
                  </div>
                ))}

                {vulnGroups.length === 0 && (
                  <div className="bg-emerald-900/20 border border-emerald-700/30 rounded-xl p-4 text-center">
                    <div className="text-2xl mb-1">✅</div>
                    <p className="text-emerald-400 text-sm font-semibold">Clean Scan</p>
                    <p className="text-xs text-gray-500 mt-1">No vulnerabilities detected</p>
                  </div>
                )}
              </div>

              {/* Main findings panel */}
              <div className="lg:col-span-3">
                {/* Filter tabs */}
                <div className="flex gap-2 mb-4 flex-wrap">
                  {FILTER_TABS.map((f) => (
                    <button
                      key={f}
                      onClick={() => setActiveFilter(f)}
                      className={`px-4 py-1.5 rounded-full text-xs font-semibold border transition ${
                        activeFilter === f
                          ? f === "All"
                            ? "bg-cyan-600 border-cyan-500 text-white"
                            : `${SEV_CONFIG[f]?.bg} ${SEV_CONFIG[f]?.border} ${SEV_CONFIG[f]?.text}`
                          : "bg-[#21262d] border-gray-700 text-gray-500 hover:border-gray-500"
                      }`}
                    >
                      {f === "All" ? `All (${(result.findings || []).length})` : `${f} (${counts[f] ?? 0})`}
                    </button>
                  ))}
                </div>

                {/* Findings list */}
                <div className="space-y-3 max-h-[65vh] overflow-y-auto pr-1">
                  {filteredFindings.length === 0 && (
                    <div className="bg-[#161b22] border border-gray-800 rounded-xl p-8 text-center text-gray-500 text-sm">
                      No {activeFilter !== "All" ? activeFilter + " " : ""}findings.
                    </div>
                  )}
                  {filteredFindings.map((f, idx) => {
                    const s = sev(f.severity);
                    return (
                      <details
                        key={idx}
                        className={`group ${s.bg} border ${s.border} rounded-xl overflow-hidden transition-all`}
                      >
                        <summary className="flex items-start gap-3 px-4 py-3 cursor-pointer list-none select-none hover:bg-white/5 transition">
                          <span className="text-xl mt-0.5">{vulnIcon(f.vuln_class || "")}</span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={`text-sm font-semibold ${s.text}`}>{f.issue || f.vuln_class}</span>
                              <span className={`text-xs px-2 py-0.5 rounded-full border ${s.border} ${s.text} font-bold shrink-0`}>
                                {f.severity}
                              </span>
                              {f.confidence && (
                                <span className="text-xs px-2 py-0.5 bg-gray-800/60 border border-gray-700 rounded-full text-gray-400">
                                  {f.confidence}
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-3 mt-1 flex-wrap">
                              {f.url && (
                                <span className="text-xs text-gray-500 font-mono truncate max-w-xs">{f.url}</span>
                              )}
                              {f.cwe && (
                                <span className="text-xs text-gray-600">{f.cwe}</span>
                              )}
                              {f.owasp && (
                                <span className="text-xs text-gray-600">{f.owasp}</span>
                              )}
                            </div>
                          </div>
                          <span className={`text-xs font-mono text-gray-500 mt-1 shrink-0 group-open:rotate-90 transition-transform`}>▶</span>
                        </summary>

                        {/* Expanded detail */}
                        <div className="px-4 pb-4 pt-0 border-t border-gray-700/40 mt-0 space-y-3">
                          {f.description && (
                            <div>
                              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Description</p>
                              <p className="text-sm text-gray-300 leading-relaxed">{f.description}</p>
                            </div>
                          )}
                          {f.remediation && (
                            <div>
                              <p className="text-xs font-semibold text-emerald-500 uppercase tracking-wider mb-1">✅ Remediation</p>
                              <p className="text-sm text-gray-300 leading-relaxed">{f.remediation}</p>
                            </div>
                          )}
                          {f.evidence && (
                            <div>
                              <p className="text-xs font-semibold text-cyan-500 uppercase tracking-wider mb-1">📋 Evidence</p>
                              <pre className="text-xs text-gray-400 bg-[#0d1117] rounded-lg p-3 overflow-x-auto whitespace-pre-wrap border border-gray-800 max-h-64 overflow-y-auto">
                                {f.evidence}
                              </pre>
                            </div>
                          )}
                          {(f.cvss_score || f.cvss_vector) && (
                            <div className="flex items-center gap-3">
                              {f.cvss_score && (
                                <span className={`text-xs px-2 py-1 rounded font-mono font-bold ${s.text} ${s.bg} border ${s.border}`}>
                                  CVSS {f.cvss_score}
                                </span>
                              )}
                              {f.cvss_vector && (
                                <span className="text-xs text-gray-600 font-mono">{f.cvss_vector}</span>
                              )}
                            </div>
                          )}
                        </div>
                      </details>
                    );
                  })}
                </div>

                {/* Summary footer */}
                <div className="mt-4 bg-[#161b22] border border-gray-800 rounded-xl px-4 py-3 flex flex-wrap gap-4 text-xs text-gray-500">
                  <span>🕷️ <strong className="text-gray-300">Target:</strong> {result.target}</span>
                  <span>🔍 <strong className="text-gray-300">Total:</strong> {(result.findings || []).length} findings</span>
                  {result.started_at && result.completed_at && (
                    <span>⏱️ <strong className="text-gray-300">Duration:</strong>{" "}
                      {Math.round((new Date(result.completed_at) - new Date(result.started_at)) / 1000)}s
                    </span>
                  )}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
