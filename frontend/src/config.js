/**
 * DevSecure360 — Frontend API Configuration
 *
 * ALL API calls in every page must use API_BASE from this file.
 * NEVER hardcode http://localhost:8000 or http://127.0.0.1:8000 anywhere.
 *
 * In development: set REACT_APP_API_BASE=http://localhost:8000 in frontend/.env
 * In production:  set REACT_APP_API_BASE=https://api.yourdomain.com in your deployment env
 */

const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:8000";

export default API_BASE;
