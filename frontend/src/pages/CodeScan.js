import { useState } from "react";
import axios from "axios";

const API_BASE = "http://localhost:8000";

export default function CodeScan() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  // New agent-related states
  const [agentLoading, setAgentLoading] = useState(false);
  const [agentMessage, setAgentMessage] = useState(null);

  const handleScan = async () => {
    if (!file) {
      alert("Please upload a source code file or ZIP first!");
      return;
    }
    setLoading(true);
    setResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(`${API_BASE}/scan/code`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(res.data);
    } catch (err) {
      console.error("Code scan error:", err);
      alert("Code scan failed. Please check backend or Bandit/Semgrep setup.");
    } finally {
      setLoading(false);
    }
  };

  // New function to call the agent endpoint
  const handleRunAgent = async () => {
    setAgentLoading(true);
    setAgentMessage(null);
    try {
      const res = await axios.post(`${API_BASE}/agent/run`);
      setAgentMessage(
        res.data.message || "Agent pipeline completed successfully."
      );
    } catch (err) {
      console.error("Agent run error:", err);
      setAgentMessage("Agent run failed. Please check backend logs.");
    } finally {
      setAgentLoading(false);
    }
  };

  return (
    <div className="p-10 min-h-screen bg-[#1B3C53] flex flex-col items-center text-gray-100 font-tektur">
      <div className="bg-[#234C6A] shadow-2xl rounded-2xl p-8 w-full max-w-3xl overflow-hidden">
        <h2 className="text-3xl font-bold mb-6 text-center text-[#F4EBD3]">
          🧠 Source Code Security Scan
        </h2>

        <div className="border-2 border-dashed border-[#456882] p-6 rounded-lg text-center mb-6 bg-[#1E1E1E]/50">
          <input
            type="file"
            onChange={(e) => setFile(e.target.files[0])}
            className="w-full px-4 py-2 mb-4 bg-white text-black rounded-md"
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
            <p>🔍 Running Bandit & Semgrep scans... please wait.</p>
          </div>
        )}

        {result && (
          <div className="mt-8 overflow-hidden">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold text-[#F4EBD3]">
                Scan Summary
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
                    <th className="border px-3 py-2 w-[25%]">File</th>
                    <th className="border px-3 py-2 w-[45%]">Issue</th>
                    <th className="border px-3 py-2 w-[15%]">Severity</th>
                    <th className="border px-3 py-2 w-[15%]">Tool</th>
                  </tr>
                </thead>
                <tbody className="bg-[#364554] text-gray-200">
                  {result.findings?.map((v, idx) => (
                    <tr
                      key={idx}
                      className="hover:bg-[#445464]/60 transition"
                    >
                      <td className="border px-3 py-2 break-words whitespace-normal text-sm max-w-[200px]">
                        {typeof v.file === "object"
                          ? JSON.stringify(v.file)
                          : v.file ?? "N/A"}
                      </td>
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
                      <td className="border px-3 py-2 text-center text-sm break-words">
                        {v.tool ?? "N/A"}
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

            {/* New Run Agent button and status */}
            <div className="mt-6 flex items-center space-x-4">
              <button
                onClick={handleRunAgent}
                disabled={agentLoading}
                className={`px-6 py-2 rounded-md text-white font-semibold transition ${
                  agentLoading
                    ? "bg-gray-500 cursor-not-allowed"
                    : "bg-[#287BDE] hover:bg-[#3A96F8]"
                }`}
              >
                {agentLoading ? "Running Agent..." : "Run Agent"}
              </button>
              {agentMessage && (
                <p className="text-sm text-[#F4EBD3]">{agentMessage}</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
