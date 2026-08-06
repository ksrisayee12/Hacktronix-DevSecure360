import { useState } from "react";
import axios from "axios";
import API_BASE from "../config";

export default function PortScan() {
  const [host, setHost] = useState("");
  const [portRange, setPortRange] = useState("1-1024");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleScan = async () => {
    if (!host) {
      alert("Please enter a host or IP address!");
      return;
    }
    setLoading(true);
    setResult(null);

    try {
      const res = await axios.post(
        `${API_BASE}/scan/port`,
        { host, port_range: portRange },
        { headers: { "Content-Type": "application/json" } }
      );
      setResult(res.data);
    } catch (err) {
      console.error("Port scan error:", err);
      alert("Port scan failed. Please check your backend connection.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-10 min-h-screen bg-[#1B3C53] flex flex-col items-center text-gray-100">
      <div className="bg-[#234C6A] shadow-2xl rounded-2xl p-8 w-full max-w-3xl overflow-hidden">
        <h2 className="text-3xl font-bold mb-6 text-center text-[#F4EBD3]">
          🔌 Port Scanner
        </h2>

        <div className="border-2 border-dashed border-[#456882] p-6 rounded-lg mb-6 bg-[#1E1E1E]/50 space-y-4">
          <input
            type="text"
            placeholder="Host or IP (e.g. 192.168.1.1 or example.com)"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            className="w-full px-4 py-2 rounded-md text-black"
          />
          <input
            type="text"
            placeholder="Port range (e.g. 1-1024)"
            value={portRange}
            onChange={(e) => setPortRange(e.target.value)}
            className="w-full px-4 py-2 rounded-md text-black"
          />
          <div className="text-center">
            <button
              onClick={handleScan}
              disabled={loading}
              className={`px-6 py-2 rounded-md text-white font-semibold transition ${
                loading ? "bg-gray-500 cursor-not-allowed" : "bg-[#456882] hover:bg-[#98A1BC]"
              }`}
            >
              {loading ? "Scanning..." : "Start Scan"}
            </button>
          </div>
        </div>

        {loading && (
          <div className="text-center text-[#DED3C4] mt-4 animate-pulse">
            <p>🔍 Scanning ports... please wait.</p>
          </div>
        )}

        {result && (
          <div className="mt-8">
            <h3 className="text-xl font-semibold text-[#F4EBD3] mb-4">
              Open Ports — {result.findings?.length ?? 0} found
            </h3>
            <div className="overflow-x-auto rounded-lg border border-[#456882] bg-[#2E3A47]">
              <table className="w-full border-collapse">
                <thead className="bg-[#456882] text-white">
                  <tr>
                    <th className="border px-3 py-2 text-left">Port</th>
                    <th className="border px-3 py-2 text-left">Service</th>
                    <th className="border px-3 py-2 text-left">Banner</th>
                    <th className="border px-3 py-2 text-center">Severity</th>
                  </tr>
                </thead>
                <tbody className="bg-[#364554] text-gray-200">
                  {result.findings?.map((f, idx) => (
                    <tr key={idx} className="hover:bg-[#445464]/60 transition">
                      <td className="border px-3 py-2 text-sm font-mono">{f.url ?? "N/A"}</td>
                      <td className="border px-3 py-2 text-sm">{f.vuln_class ?? "Unknown"}</td>
                      <td className="border px-3 py-2 text-sm text-[#D2C1B6] break-words">{f.evidence ?? "-"}</td>
                      <td className="border px-3 py-2 text-sm text-center">{f.severity ?? "Info"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
