import React from "react";
import { Shield, Cpu, Activity, BarChart3, Code2, Database } from "lucide-react";

export default function About() {
  return (
    <div className="p-10 bg-[#234C6A] min-h-screen text-[#D2C1B6]">
      <div className="max-w-4xl mx-auto text-center space-y-8">
        <h1 className="text-4xl font-extrabold text-[#F4EBD3] mb-4 tracking-wide">
          About DevSecure360
        </h1>
        <p className="text-lg leading-relaxed text-[#E5D8C7]">
          <span className="font-semibold text-[#F4EBD3]">DevSecure360</span> is a
          unified security automation platform crafted to identify and analyze
          vulnerabilities in your codebase and web applications. It seamlessly
          integrates static and dynamic analysis tools to deliver in-depth
          insights, ensuring your applications stay robust and secure.
        </p>
        <p className="text-lg leading-relaxed text-[#E5D8C7]">
          <span className="font-semibold text-[#F4EBD3]">DevSecure360</span> is intended only for testing systems you own or are authorized to test.
          Unauthorized scanning is illegal.
          The developer is not responsible for misuse.
        </p>

        <div className="border-t border-[#456882] w-1/2 mx-auto opacity-60"></div>

        <div>
          <h2 className="text-2xl font-semibold text-[#F4EBD3] mb-4">
            Key Features
          </h2>
          <div className="grid md:grid-cols-2 gap-6 text-left">
            <div className="bg-[#1B3C53] p-5 rounded-2xl shadow-lg border border-[#456882] hover:scale-[1.02] transition">
              <Shield className="text-[#DED3C4] w-7 h-7 mb-3" />
              <p className="text-[#E5D8C7] font-medium">
                Automated Code Vulnerability Scanning
              </p>
              <p className="text-sm opacity-80">
                Detect security flaws automatically using Bandit and Semgrep with
                deep contextual insights.
              </p>
            </div>
            <div className="bg-[#1B3C53] p-5 rounded-2xl shadow-lg border border-[#456882] hover:scale-[1.02] transition">
              <Activity className="text-[#DED3C4] w-7 h-7 mb-3" />
              <p className="text-[#E5D8C7] font-medium">
                External Web Application Penetration Testing
              </p>
              <p className="text-sm opacity-80">
                Leverage OWASP ZAP automation to detect vulnerabilities in live
                web environments.
              </p>
            </div>
            <div className="bg-[#1B3C53] p-5 rounded-2xl shadow-lg border border-[#456882] hover:scale-[1.02] transition">
              <BarChart3 className="text-[#DED3C4] w-7 h-7 mb-3" />
              <p className="text-[#E5D8C7] font-medium">
                Real-Time Dashboards & Insights
              </p>
              <p className="text-sm opacity-80">
                Visualize scan severity, trends, and history using dynamic charts
                and analytics.
              </p>
            </div>
            <div className="bg-[#1B3C53] p-5 rounded-2xl shadow-lg border border-[#456882] hover:scale-[1.02] transition">
              <Cpu className="text-[#DED3C4] w-7 h-7 mb-3" />
              <p className="text-[#E5D8C7] font-medium">
                Automated Scoring & Aggregation
              </p>
              <p className="text-sm opacity-80">
                Generate risk scores intelligently based on severity and frequency
                of vulnerabilities.
              </p>
            </div>
          </div>
        </div>

        <div className="border-t border-[#456882] w-1/2 mx-auto opacity-60"></div>

        <div>
          <h2 className="text-2xl font-semibold text-[#F4EBD3] mb-4">
            Technology Stack
          </h2>
          <div className="grid md:grid-cols-2 gap-6 text-left">
            <div className="flex items-start gap-3 bg-[#1B3C53] p-5 rounded-2xl shadow-lg border border-[#456882]">
              <Code2 className="text-[#DED3C4] w-6 h-6 mt-1" />
              <div>
                <p className="text-[#F4EBD3] font-medium">Backend</p>
                <p className="text-sm opacity-80">FastAPI (Python)</p>
              </div>
            </div>
            <div className="flex items-start gap-3 bg-[#1B3C53] p-5 rounded-2xl shadow-lg border border-[#456882]">
              <Code2 className="text-[#DED3C4] w-6 h-6 mt-1" />
              <div>
                <p className="text-[#F4EBD3] font-medium">Frontend</p>
                <p className="text-sm opacity-80">React + TailwindCSS</p>
              </div>
            </div>
            <div className="flex items-start gap-3 bg-[#1B3C53] p-5 rounded-2xl shadow-lg border border-[#456882]">
              <Shield className="text-[#DED3C4] w-6 h-6 mt-1" />
              <div>
                <p className="text-[#F4EBD3] font-medium">Security Tools</p>
                <p className="text-sm opacity-80">
                  Bandit, Semgrep, OWASP ZAP
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3 bg-[#1B3C53] p-5 rounded-2xl shadow-lg border border-[#456882]">
              <Database className="text-[#DED3C4] w-6 h-6 mt-1" />
              <div>
                <p className="text-[#F4EBD3] font-medium">Database</p>
                <p className="text-sm opacity-80">
                  JSON/SQLite-based scan storage
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-10 text-lg italic text-[#E5D8C7] opacity-90">
          Built for developers who care about{" "}
          <span className="text-[#F4EBD3] font-semibold">secure code.</span>
        </div>
      </div>
    </div>
  );
}
