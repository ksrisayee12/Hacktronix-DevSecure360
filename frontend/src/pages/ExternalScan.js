import { useState } from "react";
import axios from "axios";

const API_BASE = "http://localhost:8000";

export default function ExternalScan() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleScan = async () => {
    if (!url) {
      alert("Please enter a website URL first!");
      return;
    }
    setLoading(true);
    setResult(null);

    try {
      const res = await axios.post(
        `${API_BASE}/scan/external`,
        { url },
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

  return (
    <div className="p-10 min-h-screen bg-[#1B3C53] flex flex-col items-center text-gray-100 font-tektur">
      <div className="bg-[#234C6A] shadow-2xl rounded-2xl p-8 w-full max-w-3xl overflow-hidden">
        <h2 className="text-3xl font-bold mb-6 text-center text-[#F4EBD3]">
          🌐 External Vulnerability Scan
        </h2>

        <div className="border-2 border-dashed border-[#456882] p-6 rounded-lg text-center mb-6 bg-[#1E1E1E]/50">
          <input
            type="text"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="w-full px-4 py-2 mb-4 rounded-md text-black"
          />
          <button
            onClick={handleScan}
            disabled={loading}
            className={`px-6 py-2 rounded-md text-white font-semibold transition ${
              loading
                ? "bg-gray-500 cursor-not-allowed"
                : "bg-[#456882] hover:bg-[#98A1BC]"
            }`}
          >
            {loading ? "Scanning..." : "Start Scan"}
          </button>
        </div>

        {loading && (
          <div className="text-center text-[#DED3C4] mt-4 animate-pulse">
            <p>🔍 Running external scan... please wait.</p>
          </div>
        )}

        {result && (
          <div className="mt-8 overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold text-[#F4EBD3]">
                Scan Results
              </h3>
              <span
                className={`px-3 py-1 rounded-full text-white text-sm font-bold ${
                  result.score?.score >= 80
                    ? "bg-green-600"
                    : result.score?.score >= 60
                    ? "bg-yellow-500"
                    : "bg-red-600"
                }`}
              >
                Score: {result.score?.score ?? 0}%
              </span>
            </div>

            <div className="overflow-x-auto max-h-[500px] overflow-y-auto rounded-lg border border-[#456882] bg-[#2E3A47]">
              <table className="w-full border-collapse table-fixed">
                <thead className="sticky top-0 z-10 bg-[#456882] text-white">
                  <tr>
                    <th className="border px-3 py-2 w-[45%]">Vulnerability</th>
                    <th className="border px-3 py-2 w-[20%]">Severity</th>
                    <th className="border px-3 py-2 w-[35%]">Location</th>
                  </tr>
                </thead>
                <tbody className="bg-[#364554] text-gray-200">
                  {result.findings?.map((v, idx) => (
                    <tr
                      key={idx}
                      className="hover:bg-[#445464]/60 transition"
                    >
                      <td className="border px-3 py-2 break-words whitespace-normal text-sm max-w-[300px]">
                        {typeof v.issue === "object"
                          ? JSON.stringify(v.issue)
                          : v.issue ?? "N/A"}
                      </td>
                      <td
                        className={`border px-3 py-2 font-semibold text-sm text-center ${
                          v.severity === "High"
                            ? "text-red-400"
                            : v.severity === "Medium"
                            ? "text-yellow-400"
                            : "text-green-400"
                        }`}
                      >
                        {v.severity ?? "N/A"}
                      </td>
                      <td className="border px-3 py-2 break-words whitespace-normal text-sm max-w-[250px] text-center">
                        {v.resource ?? v.location ?? "N/A"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-6 bg-[#1E1E1E]/40 p-4 rounded-lg text-sm">
              <p>
                <strong>Total Findings:</strong>{" "}
                {result.findings?.length ?? 0}
              </p>
              <p>
                <strong>High:</strong> {result.score?.counts?.High ?? 0} |{" "}
                <strong>Medium:</strong> {result.score?.counts?.Medium ?? 0} |{" "}
                <strong>Low:</strong> {result.score?.counts?.Low ?? 0}
              </p>
              <p>
                <strong>Last Calculated:</strong>{" "}
                {result.score?.calculated_at
                  ? new Date(result.score.calculated_at).toLocaleString()
                  : "N/A"}
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
