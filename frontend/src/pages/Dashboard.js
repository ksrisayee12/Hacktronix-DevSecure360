import React, { useState, useEffect } from "react";
import {PieChart, Pie, Cell, Tooltip, Legend, LineChart, Line, XAxis, YAxis, ResponsiveContainer, CartesianGrid,} from "recharts";

const COLORS = ["#555879", "#98A1BC", "#DED3C4", "#F4EBD3"];

function normalizeSeverity(s) {
  if (!s && s !== 0) return "Low";
  const sev = String(s).trim().toLowerCase();
  if (sev.includes("crit")) return "Critical";
  if (sev.includes("high") || sev.includes("error")) return "High";
  if (sev.includes("med") || sev.includes("warn")) return "Medium";
  if (sev.includes("low") || sev.includes("info")) return "Low";
  return "Low";
}

function countSeverities(findings = []) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach((f) => {
    const n = normalizeSeverity(f.severity || f.risk || f.level);
    if (counts[n] !== undefined) counts[n]++;
  });
  return [
    { name: "Critical", value: counts.Critical },
    { name: "High", value: counts.High },
    { name: "Medium", value: counts.Medium },
    { name: "Low", value: counts.Low },
  ];
}

function dayLabelFromISO(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
}

function last7DayLabels() {
  const arr = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    arr.push(d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" }));
  }
  return arr;
}

export default function Dashboard() {
  const [scanHistory, setScanHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchHistory() {
      try {
        const res = await fetch("http://localhost:8000/history");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setScanHistory(Array.isArray(data.history) ? data.history : []);
      } catch (err) {
        console.error("Error fetching scan history:", err);
        setError(err.message || String(err));
      } finally {
        setLoading(false);
      }
    }
    fetchHistory();
  }, []);

  if (loading) {
    return (
      <div className="p-10 bg-[#234C6A] min-h-screen text-[#D2C1B6] flex items-center justify-center">
        <p className="text-2xl">Loading real data...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-10 bg-[#234C6A] min-h-screen text-[#D2C1B6] flex items-center justify-center">
        <p className="text-red-400">Error fetching history: {error}</p>
      </div>
    );
  }

  const getType = (scan) => scan.scan_type || scan.type || "external";

  const codeScanFindings = scanHistory
    .filter((s) => getType(s) === "code")
    .flatMap((s) => s.findings || []);
  const externalScanFindings = scanHistory
    .filter((s) => getType(s) === "external")
    .flatMap((s) => s.findings || []);

  const codeScanData = countSeverities(codeScanFindings);
  const externalScanData = countSeverities(externalScanFindings);

  const recentScans = (scanHistory.slice(0, 5) || []).map((scan, i) => {
    const findings = scan.findings || [];
    const counts = countSeverities(findings).reduce(
      (acc, it) => ({ ...acc, [it.name.toLowerCase()]: it.value }),
      {}
    );
    return {
      id: i,
      name: getType(scan) === "code" ? "Code Scan" : "External Scan",
      date: scan.timestamp ? new Date(scan.timestamp).toLocaleString() : "N/A",
      high: counts.high || 0,
      medium: counts.medium || 0,
      low: counts.low || 0,
      score: scan.score ?? null,
    };
  });

  const labels = last7DayLabels();
  const trendMap = {};
  labels.forEach((lbl) => {
    trendMap[lbl] = { date: lbl, code: 0, external: 0 };
  });

  scanHistory.forEach((scan) => {
    const ts = scan.timestamp || scan.time || scan.created_at || scan.date;
    if (!ts) return;
    const lbl = dayLabelFromISO(ts);
    if (!(lbl in trendMap)) return;
    const cnt = (scan.findings || []).length;
    if (getType(scan) === "code") trendMap[lbl].code += cnt;
    else trendMap[lbl].external += cnt;
  });

  const trendData = Object.values(trendMap); 

  const totalScans = scanHistory.length;
  const lastScan = scanHistory[0];
  const lastScanDate = lastScan ? new Date(lastScan.timestamp || lastScan.time || lastScan.date || lastScan.created_at) : null;
  const timeSinceLastScan = lastScanDate ? Math.floor((Date.now() - lastScanDate.getTime()) / (1000 * 60)) : null;
  const averageScore = totalScans ? Math.round((scanHistory.reduce((s, x) => s + (x.score || 0), 0) / totalScans)) : 0;
  const avgRisk = averageScore >= 75 ? "Critical" : averageScore >= 50 ? "High" : averageScore >= 25 ? "Medium" : "Low";

  return (
    <div className="p-10 bg-[#234C6A] min-h-screen text-[#D2C1B6]">
      <h2 className="text-3xl font-bold mb-8 text-center">Security Dashboard</h2>

      <div className="flex flex-col lg:flex-row justify-around items-center gap-10 mb-12">
        <div className="bg-[#1B3C53] p-6 rounded-2xl shadow-lg border border-[#456882]">
          <h3 className="text-xl mb-4 font-semibold text-[#F4EBD3] text-center">
            Code Scan Severity
          </h3>
          <PieChart width={350} height={300}>
            <Pie data={codeScanData} cx={175} cy={150} outerRadius={100} dataKey="value">
              {codeScanData.map((entry, index) => (
                <Cell key={index} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ backgroundColor: "#1B3C53", border: "1px solid #456882", color: "#D2C1B6" }} itemStyle={{ color: "#F4EBD3" }} />
            <Legend wrapperStyle={{ color: "#F4EBD3" }} />
          </PieChart>
        </div>

        <div className="bg-[#1B3C53] p-6 rounded-2xl shadow-lg border border-[#456882]">
          <h3 className="text-xl mb-4 font-semibold text-[#F4EBD3] text-center">
            External Scan Severity
          </h3>
          <PieChart width={350} height={300}>
            <Pie data={externalScanData} cx={175} cy={150} outerRadius={100} dataKey="value">
              {externalScanData.map((entry, index) => (
                <Cell key={index} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ backgroundColor: "#1B3C53", border: "1px solid #456882", color: "#D2C1B6" }} itemStyle={{ color: "#F4EBD3" }} />
            <Legend wrapperStyle={{ color: "#F4EBD3" }} />
          </PieChart>
        </div>
      </div>

      <div className="bg-[#1B3C53] p-6 rounded-2xl shadow-lg border border-[#456882] w-80 text-center mx-auto mb-12">
        <p className="text-lg mb-3">
          <span className="font-semibold text-[#F4EBD3]">Total Scans:</span> {totalScans}
        </p>
        <p className="text-lg mb-3">
          <span className="font-semibold text-[#F4EBD3]">Last Scan:</span>{" "}
          {timeSinceLastScan !== null ? `${timeSinceLastScan} minutes ago` : "N/A"}
        </p>
        <p className="text-lg">
          <span className="font-semibold text-[#F4EBD3]">Average Risk Level:</span> {avgRisk}
        </p>
      </div>

      <div className="bg-[#1B3C53] p-6 rounded-2xl shadow-lg border border-[#456882] mb-12">
        <h3 className="text-xl mb-4 font-semibold text-[#F4EBD3] text-center">7-Day Scan Findings Trend</h3>
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#456882" />
              <XAxis dataKey="date" stroke="#D2C1B6" />
              <YAxis stroke="#D2C1B6" />
              <Tooltip contentStyle={{ backgroundColor: "#1B3C53", border: "1px solid #456882", color: "#F4EBD3" }} />
              <Legend wrapperStyle={{ color: "#F4EBD3" }} />
              <Line type="monotone" dataKey="code" stroke="#98A1BC" strokeWidth={2} />
              <Line type="monotone" dataKey="external" stroke="#DED3C4" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-[#1B3C53] p-6 rounded-2xl shadow-lg border border-[#456882]">
        <h3 className="text-xl mb-4 font-semibold text-[#F4EBD3] text-center">Recent Scans</h3>
        <table className="w-full text-left border-collapse text-[#D2C1B6]">
          <thead>
            <tr className="border-b border-[#456882] text-[#F4EBD3]">
              <th className="py-2 px-3">Scan Name</th>
              <th className="py-2 px-3">Date</th>
              <th className="py-2 px-3">High</th>
              <th className="py-2 px-3">Medium</th>
              <th className="py-2 px-3">Low</th>
            </tr>
          </thead>
          <tbody>
            {recentScans.map((scan) => (
              <tr key={scan.id} className="border-t border-[#456882] hover:bg-[#284E68] transition">
                <td className="py-2 px-3">{scan.name}</td>
                <td className="py-2 px-3">{scan.date}</td>
                <td className="py-2 px-3 text-red-400">{scan.high}</td>
                <td className="py-2 px-3 text-yellow-400">{scan.medium}</td>
                <td className="py-2 px-3 text-green-400">{scan.low}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}