import { useState } from "react";
import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import CodeScan from "./pages/CodeScan";
import ExternalScan from "./pages/ExternalScan";
import PortScan from "./pages/PortScan";
import History from "./pages/History";
import About from "./pages/About";
import "./index.css";
import logo from "./assets/logo (2).png";

function App() {
  const [menuOpen, setMenuOpen] = useState(false);

  const navLinks = [
    { to: "/",              label: "Dashboard" },
    { to: "/code-scan",     label: "Code Scan" },
    { to: "/external-scan", label: "External Scan" },
    { to: "/port-scan",     label: "Port Scan" },
    { to: "/history",       label: "History" },
    { to: "/about",         label: "About" },
  ];

  return (
    <Router>
      <nav className="flex justify-between items-center px-6 md:px-10 py-4 bg-[#031323] shadow-md border-b-2 border-[#456882] sticky top-0 z-50">
        <NavLink to="/" className="flex items-center space-x-3">
          <img src={logo} alt="DevSecure360 Logo" className="h-10 w-auto object-contain" />
          <h1 className="font-bold text-2xl text-[#D2C1B6] tracking-wide whitespace-nowrap">
            DevSecure360
          </h1>
        </NavLink>

        {/* Hamburger (mobile) */}
        <button
          className="md:hidden text-[#D2C1B6] focus:outline-none"
          onClick={() => setMenuOpen(!menuOpen)}
        >
          {menuOpen ? (
            <svg xmlns="http://www.w3.org/2000/svg" className="h-7 w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          ) : (
            <svg xmlns="http://www.w3.org/2000/svg" className="h-7 w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          )}
        </button>

        {/* Desktop nav */}
        <div className="hidden md:flex space-x-6 text-lg font-medium">
          {navLinks.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                `transition-all duration-300 pb-1 ${
                  isActive
                    ? "text-[#F4EBD3] border-b-2 border-[#D2C1B6]"
                    : "text-[#DED3C4] hover:text-[#F4EBD3]"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </div>
      </nav>

      {/* Mobile dropdown */}
      {menuOpen && (
        <div className="md:hidden bg-[#031323] border-t border-[#456882] flex flex-col items-center py-4 space-y-3 text-lg font-medium shadow-lg">
          {navLinks.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              onClick={() => setMenuOpen(false)}
              className={({ isActive }) =>
                `transition-all duration-300 ${
                  isActive ? "text-[#F4EBD3] font-semibold" : "text-[#DED3C4] hover:text-[#F4EBD3]"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </div>
      )}

      <div className="bg-[#234C6A] min-h-screen text-[#D2C1B6]">
        <Routes>
          <Route path="/"              element={<Dashboard />} />
          <Route path="/code-scan"     element={<CodeScan />} />
          <Route path="/external-scan" element={<ExternalScan />} />
          <Route path="/port-scan"     element={<PortScan />} />
          <Route path="/history"       element={<History />} />
          <Route path="/about"         element={<About />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
