import React, { useEffect, useState } from "react";

export default function History() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchHistory() {
      try {
        const res = await fetch("http://127.0.0.1:8000/history");
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

  return (
    <div className="p-6 bg-[#1B3C53] min-h-screen text-white">
      <h1 className="text-3xl font-bold mb-4">Scan History</h1>

      {loading ? (
        <p>Loading previous scans...</p>
      ) : history.length === 0 ? (
        <p>No previous scans found.</p>
      ) : (
        <div className="grid md:grid-cols-2 gap-4">
          {history.map((item, idx) => (
            <div
              key={idx}
              className="bg-[#234C6A] p-4 rounded-xl shadow-lg border border-[#456882]"
            >
              <h2 className="text-xl font-semibold mb-1 capitalize">
                {item.type} Scan
              </h2>
              <p className="text-sm text-[#D2C1B6] mb-2">
                {new Date(item.timestamp).toLocaleString()}
              </p>
              <p>
                <strong>Score:</strong> {item.score?.toFixed(1) ?? 0} / 100
              </p>
              <p>
                <strong>Findings:</strong> {item.findings?.length ?? 0}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
