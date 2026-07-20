import React, { useEffect, useState } from "react";
import API_BASE from "../config";

export default function History() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchHistory() {
      try {
        const res = await fetch(`${API_BASE}/history`);
        const data = await res.json();
        setHistory(data.history || []);
      } catch (err) {
        console.error("Failed to load history:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchHistory();
  }, []);

  const gradeColor = (grade) => {
    if (grade === "A") return "text-green-400";
    if (grade === "B") return "text-blue-400";
    if (grade === "C") return "text-yellow-400";
    if (grade === "D") return "text-orange-400";
    return "text-red-400";
  };

  const scanTypeLabel = (type) => {
    const labels = { sast: "Code Scan", dast: "External Scan", port: "Port Scan", secret: "Secret Scan" };
    return labels[type] || type;
  };

  return (
    <div className="p-6 bg-[#1B3C53] min-h-screen text-white">
      <h1 className="text-3xl font-bold mb-6">Scan History</h1>

      {loading ? (
        <p className="text-[#DED3C4]">Loading previous scans...</p>
      ) : history.length === 0 ? (
        <p className="text-[#DED3C4]">No previous scans found.</p>
      ) : (
        <div className="grid md:grid-cols-2 gap-4">
          {history.map((item, idx) => (
            <div
              key={idx}
              className="bg-[#234C6A] p-4 rounded-xl shadow-lg border border-[#456882]"
            >
              <div className="flex justify-between items-center mb-2">
                <h2 className="text-xl font-semibold capitalize">
                  {scanTypeLabel(item.type)}
                </h2>
                <span className={`text-2xl font-bold ${gradeColor(item.score?.grade)}`}>
                  {item.score?.grade ?? "?"}
                </span>
              </div>
              <p className="text-sm text-[#D2C1B6] mb-2">
                {item.timestamp ? new Date(item.timestamp).toLocaleString() : "Unknown time"}
              </p>
              <p><strong>Score:</strong> {item.score?.score ?? 0} / 100</p>
              <p><strong>Findings:</strong> {item.findings?.length ?? 0}</p>
              {item.score?.counts && (
                <p className="text-sm text-[#D2C1B6] mt-1">
                  Critical: {item.score.counts.Critical ?? 0} |
                  High: {item.score.counts.High ?? 0} |
                  Medium: {item.score.counts.Medium ?? 0} |
                  Low: {item.score.counts.Low ?? 0}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
