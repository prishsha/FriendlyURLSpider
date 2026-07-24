// Base URL for the Flask backend.
// In production (Vercel), set REACT_APP_API_URL to your Render backend URL,
// e.g. https://webspidey-backend.onrender.com
// Locally, it falls back to localhost:5000 (matches package.json's "proxy",
// but works even when the proxy doesn't, e.g. after `npm run build`).
export const API_URL = process.env.REACT_APP_API_URL || "http://localhost:5000";
