// Lancement en local pour essayer le portail : node scripts/dev.mjs (avec DATABASE_URL et CODE_ADMIN dans l'environnement).
// Reprend les réécritures de vercel.json : /api/... vers la fonction, le reste depuis public/.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import handler from "../api/h.js";

const PORT = +process.env.PORT || 3000;
const TYPES = { ".png": "image/png", ".txt": "text/plain" };
http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  if (u.pathname === "/" || u.pathname === "/index.html") req.url = "/api/h?p=page";
  else if (u.pathname === "/connexion") req.url = "/api/h?p=connexion";
  else if (u.pathname.startsWith("/api/")) req.url = "/api/h?p=" + encodeURIComponent(u.pathname.slice(5)) + (u.search ? "&" + u.search.slice(1) : "");
  else {
    const f = path.join(process.cwd(), "public", path.normalize(u.pathname).replace(/^(\.\.[/\\])+/, ""));
    if (fs.existsSync(f) && fs.statSync(f).isFile()) { res.setHeader("Content-Type", TYPES[path.extname(f)] || "application/octet-stream"); return res.end(fs.readFileSync(f)); }
    res.statusCode = 404; return res.end("Introuvable");
  }
  // En local il n'y a pas de HTTPS : le cookie Secure est retiré pour que le navigateur le garde.
  const set = res.setHeader.bind(res);
  res.setHeader = (k, v) => set(k, k.toLowerCase() === "set-cookie" ? String(v).replace("; Secure", "") : v);
  handler(req, res);
}).listen(PORT, () => console.log(`Portail en local : http://localhost:${PORT}`));
