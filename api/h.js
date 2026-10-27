// Serveur du portail DSV Angers (fonction Vercel) : connexion par code personnel, menu des applis,
// gestion des personnes, des codes et des droits. Les applis Planning et Gestion des véhicules gardent
// leur propre base : le portail leur passe un jeton signé à l'ouverture, puis répond à leurs vérifications.
// Ce dépôt est public : aucun code ni aucune clé ici, tout est réglé dans Vercel.
import pg from "pg";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const read = f => fs.readFileSync(path.join(ROOT, f));
// Code de secours réglé dans Vercel : il ouvre le portail au premier lancement, ou si l'administrateur perd son code.
const CODE_ADMIN = process.env.CODE_ADMIN || "";
const NOM_ADMIN = (process.env.NOM_ADMIN || "Administrateur").trim().slice(0, 40);
const MIN_CODE = 10;
const DB_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || "";
const SECRET = crypto.createHash("sha256").update([process.env.SESSION_SECRET || "", DB_URL, CODE_ADMIN].join("|")).digest("hex");
const SESSION_S = 12 * 3600;
// Clé partagée avec les deux applis (même valeur dans les trois projets Vercel) et adresses des applis.
const CLE_PORTAIL = process.env.CLE_PORTAIL || "";
const CLE_OK = CLE_PORTAIL.length >= 32;
const url_ = v => String(v || "").trim().replace(/\/+$/, "");
const APPS = {
  planning: { nom: "Plannings", url: url_(process.env.PLANNING_URL), niveaux: ["aucun", "modif"] },
  flotte: { nom: "Gestion des véhicules", url: url_(process.env.FLOTTE_URL), niveaux: ["aucun", "consult", "modif"] }
};
const NIVEAU_NOM = { aucun: "pas d'accès", consult: "consultation", modif: "modification" };
const JETON_S = 60;

let pool;
function db() {
  if (!pool) pool = new pg.Pool({ connectionString: DB_URL, max: 3, connectionTimeoutMillis: 15000, query_timeout: 20000, ssl: /localhost|127\.0\.0\.1/.test(DB_URL) ? false : { rejectUnauthorized: true } });
  return pool;
}
const q = (text, params) => db().query(text, params);

let ready;
async function init() {
  await q(`CREATE TABLE IF NOT EXISTS personnes (id text PRIMARY KEY, nom text NOT NULL, admin boolean NOT NULL DEFAULT false, actif boolean NOT NULL DEFAULT true,
    cle text NOT NULL UNIQUE, provisoire boolean NOT NULL DEFAULT false, planning text NOT NULL DEFAULT 'aucun', flotte text NOT NULL DEFAULT 'aucun',
    code_le timestamptz NOT NULL DEFAULT now(), vu timestamptz, cree timestamptz NOT NULL DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS sessions (sid text PRIMARY KEY, pid text NOT NULL, exp timestamptz NOT NULL, fin boolean NOT NULL DEFAULT false)`);
  await q(`CREATE TABLE IF NOT EXISTS echecs (ip text NOT NULL, t timestamptz NOT NULL DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS reglages (k text PRIMARY KEY, v text NOT NULL)`);
  await q(`CREATE TABLE IF NOT EXISTS journal (id bigserial PRIMARY KEY, t timestamptz NOT NULL DEFAULT now(), qui text NOT NULL, texte text NOT NULL)`);
  await q(`INSERT INTO reglages (k, v) VALUES ('poivre', $1) ON CONFLICT (k) DO NOTHING`, [crypto.randomBytes(32).toString("hex")]);
}

// Codes personnels : gardés sous forme d'empreinte, comme dans le planning (même calcul, pour pouvoir reprendre ses codes).
const normCode = c => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
let poivre;
async function cleDe(code) {
  if (!poivre) poivre = (await q(`SELECT v FROM reglages WHERE k = 'poivre'`)).rows[0].v;
  return crypto.createHmac("sha256", poivre).update(normCode(code)).digest("hex");
}
function sameCode(a, b) {
  const x = crypto.createHash("sha256").update(String(a)).digest(), y = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}
// La connexion se fait au code seul : deux personnes ne peuvent pas avoir le même.
async function codeRefuse(code, id) {
  const n = normCode(code);
  if (n.length < MIN_CODE) return `Le code doit avoir au moins ${MIN_CODE} lettres ou chiffres`;
  if (/^(.)\1+$/.test(n) || "0123456789012345678901234567890123456789".includes(n) || "ABCDEFGHIJKLMNOPQRSTUVWXYZ".includes(n)) return "Code trop simple : évitez les suites et les caractères répétés";
  if (CODE_ADMIN && n === normCode(CODE_ADMIN)) return "Ce code n'est pas utilisable, choisis-en un autre";
  if ((await q(`SELECT 1 FROM personnes WHERE cle = $1 AND id <> $2`, [await cleDe(code), id || ""])).rows.length) return "Ce code n'est pas utilisable, choisis-en un autre";
  return null;
}
// Code provisoire : 10 caractères sans les lettres et chiffres qu'on confond (O/0, I/1).
const ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
async function codeProvisoire() {
  for (;;) {
    const b = crypto.randomBytes(10), c = [...b].map(x => ALPHA[x % ALPHA.length]).join("");
    if (!(await codeRefuse(c, ""))) return c.slice(0, 5) + " " + c.slice(5);
  }
}

// Session du portail : cookie "sid.signature", la session est en base pour pouvoir la terminer (déconnexion).
const sign = s => crypto.createHmac("sha256", SECRET).update(s).digest("base64url");
const cookieDe = sid => `portail=${sid}.${sign(sid)}; Path=/; HttpOnly; Secure; SameSite=Lax`;
const COOKIE_VIDE = "portail=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
async function ouvrirSession(pid) {
  const sid = crypto.randomBytes(24).toString("base64url");
  await q(`DELETE FROM sessions WHERE exp < now() - interval '1 day'`);
  await q(`INSERT INTO sessions (sid, pid, exp) VALUES ($1, $2, now() + make_interval(secs => $3))`, [sid, pid, SESSION_S]);
  return sid;
}
const ADMIN_SECOURS = () => ({ id: "admin", nom: NOM_ADMIN, admin: true, actif: true, provisoire: false, planning: "modif", flotte: "modif", secours: true });
// La personne est relue à chaque appel : un accès retiré ou une session terminée coupe tout de suite.
async function sessionDe(sid) {
  const s = (await q(`SELECT pid FROM sessions WHERE sid = $1 AND NOT fin AND exp > now()`, [sid])).rows[0];
  if (!s) return null;
  if (s.pid === "admin") return CODE_ADMIN.length >= MIN_CODE ? { ...ADMIN_SECOURS(), sid } : null;
  const p = (await q(`SELECT id, nom, admin, provisoire, planning, flotte FROM personnes WHERE id = $1 AND actif`, [s.pid])).rows[0];
  return p ? { ...p, sid } : null;
}
async function session(req) {
  const m = /(?:^|;\s*)portail=([^;]+)/.exec(req.headers.cookie || "");
  if (!m) return null;
  const [sid, sig] = m[1].split(".");
  if (!sid || !sig) return null;
  const good = sign(sid);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  return sessionDe(sid);
}
// Codes faux : 10 par adresse IP et 100 au total en 10 minutes, ensuite la connexion est suspendue.
const ipOf = req => String(req.headers["x-real-ip"] || req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "?";
async function blocked(ip) {
  await q(`DELETE FROM echecs WHERE t < now() - interval '10 minutes'`);
  const r = await q(`SELECT count(*) FILTER (WHERE ip = $1)::int AS ip, count(*)::int AS tout FROM echecs`, [ip]);
  return r.rows[0].ip >= 10 || r.rows[0].tout >= 100;
}

// Jeton d'ouverture d'une appli : qui, ses droits, la session du portail ; valable 1 minute, signé avec CLE_PORTAIL.
const signP = s => crypto.createHmac("sha256", CLE_PORTAIL).update(s).digest("base64url");
function jetonPour(app, ses) {
  const o = { app, sid: ses.sid, id: ses.id, nom: ses.nom, admin: !!ses.admin, planning: ses.planning, flotte: ses.flotte,
    exp: Math.floor(Date.now() / 1000) + JETON_S, jti: crypto.randomBytes(12).toString("base64url") };
  const b = Buffer.from(JSON.stringify(o)).toString("base64url");
  return b + "." + signP("jeton." + b);
}
// Appel d'une appli (vérification des droits, toutes les 5 minutes) : la clé partagée sert de mot de passe.
function cleAppelOk(req) {
  const a = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  return CLE_OK && !!a && sameCode(a, CLE_PORTAIL);
}

const clean = (v, n) => String(v == null ? "" : v).replace(/[\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const niveau = (app, v) => APPS[app].niveaux.includes(v) ? v : "aucun";
const newId = () => "p" + crypto.randomBytes(5).toString("hex");
const log = (qui, texte) => q(`INSERT INTO journal (qui, texte) VALUES ($1, $2)`, [qui, texte.slice(0, 400)]);

function send(res, status, type, body, cookie) {
  res.statusCode = status;
  res.setHeader("Content-Type", type);
  res.setHeader("Cache-Control", "no-store");
  if (type.startsWith("text/html")) res.setHeader("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'");
  if (cookie) res.setHeader("Set-Cookie", cookie);
  res.end(body);
}
const json = (res, status, o, cookie) => send(res, status, "application/json; charset=utf-8", JSON.stringify(o), cookie);
const text = (res, status, t) => send(res, status, "text/plain; charset=utf-8", t);
const redirect = (res, to, cookie) => { res.statusCode = 302; res.setHeader("Location", to); res.setHeader("Cache-Control", "no-store"); if (cookie) res.setHeader("Set-Cookie", cookie); res.end(); };
async function body(req, limit = 64 * 1024) {
  // Vercel peut avoir déjà lu le corps de la requête : on le reprend alors tel quel.
  let pre;
  try { pre = req.body; } catch (_) {}
  if (pre != null && pre !== "") {
    const b = Buffer.isBuffer(pre) ? pre : Buffer.from(typeof pre === "string" ? pre : JSON.stringify(pre));
    if (b.length > limit) throw new Error("trop gros");
    return b;
  }
  const parts = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > limit) throw new Error("trop gros"); parts.push(c); }
  return Buffer.concat(parts);
}
const jsonBody = async (req, limit) => { try { return JSON.parse((await body(req, limit)).toString("utf8")); } catch (_) { return undefined; } };
const page = (res, f) => send(res, 200, "text/html; charset=utf-8", read(f));
const PERSONNE = `SELECT id, nom, admin, actif, provisoire, planning, flotte, code_le, vu FROM personnes`;

export default async function handler(req, res) {
  const url = new URL(req.url, "http://x");
  // Vercel transmet le chemin réécrit dans ?p= ; à défaut, on le reprend de l'adresse d'origine.
  let p = url.searchParams.get("p");
  if (p == null) p = url.pathname === "/" || url.pathname === "/index.html" ? "page" : url.pathname.replace(/^\/(api\/)?/, "");
  p = "/" + String(p).replace(/^\/+/, "");
  const method = req.method;
  let m;
  try {
    if (p === "/health") {
      if (!DB_URL) return json(res, 500, { ok: false, base: "absente : reliez une base Neon au projet (onglet Storage), puis Redeploy" });
      try { const t = Date.now(); await q("SELECT 1"); return json(res, 200, { ok: true, base: "connectée", ms: Date.now() - t, cle: CLE_OK, planning: !!APPS.planning.url, flotte: !!APPS.flotte.url }); }
      catch (e) { return json(res, 500, { ok: false, base: "erreur", detail: String(e.message || e).slice(0, 200) }); }
    }
    if (!DB_URL) return text(res, 500, "Base de données non configurée : ajoutez une base Neon au projet Vercel.");
    if (!ready) ready = init().catch(e => { ready = null; throw e; });
    await ready;

    // Vérification demandée par une appli : la session du portail est-elle toujours ouverte, et la personne a-t-elle encore le droit ?
    if (p === "/verif" && method === "POST") {
      if (!cleAppelOk(req)) return text(res, 401, "Clé refusée");
      const o = await jsonBody(req, 2000) || {};
      const ses = APPS[o.app] && typeof o.sid === "string" ? await sessionDe(o.sid) : null;
      if (!ses || ses.provisoire || ses[o.app] === "aucun") return json(res, 403, { ok: false });
      return json(res, 200, { ok: true, id: ses.id, nom: ses.nom, admin: !!ses.admin, planning: ses.planning, flotte: ses.flotte });
    }

    // Une écriture doit venir de la page du portail elle-même.
    if (["PUT", "POST", "DELETE"].includes(method)) {
      const o = req.headers.origin;
      if (o && o !== `https://${req.headers.host}` && o !== `http://${req.headers.host}`) return text(res, 403, "Origine refusée");
    }
    if (p === "/login" && method === "POST") {
      const ip = ipOf(req);
      if (await blocked(ip)) return json(res, 429, { ok: false, wait: true });
      const code = String((await jsonBody(req, 2000) || {}).code || "");
      if (code && CODE_ADMIN.length >= MIN_CODE && sameCode(normCode(code), normCode(CODE_ADMIN))) {
        await log(NOM_ADMIN, "Connexion avec le code de secours");
        return json(res, 200, { ok: true }, cookieDe(await ouvrirSession("admin")));
      }
      if (normCode(code).length >= MIN_CODE) {
        const r = (await q(`UPDATE personnes SET vu = now() WHERE cle = $1 AND actif RETURNING id, provisoire`, [await cleDe(code)])).rows[0];
        if (r) return json(res, 200, { ok: true, provisoire: r.provisoire }, cookieDe(await ouvrirSession(r.id)));
      }
      if (CODE_ADMIN.length < MIN_CODE && !(await q(`SELECT 1 FROM personnes LIMIT 1`)).rows.length)
        return text(res, 503, "Code de secours non réglé dans Vercel : ajoutez CODE_ADMIN (10 caractères minimum), puis Redeploy.");
      await q(`INSERT INTO echecs (ip) VALUES ($1)`, [ip]); await new Promise(r => setTimeout(r, 1000));
      return json(res, 401, { ok: false });
    }
    if (p === "/connexion") return page(res, "pages/connexion.html");
    // Déconnexion : la session du portail est terminée, les applis ouvertes avec elle se ferment à leur prochaine vérification.
    if (p === "/logout") {
      const mc = /(?:^|;\s*)portail=([^.;]+)\./.exec(req.headers.cookie || "");
      if (mc) await q(`UPDATE sessions SET fin = true WHERE sid = $1`, [mc[1]]);
      return method === "GET" ? redirect(res, "/connexion?sortie=1", COOKIE_VIDE) : json(res, 200, { ok: true }, COOKIE_VIDE);
    }

    const ses = await session(req);
    if (!ses) {
      if (p === "/page") return page(res, "pages/connexion.html");
      if (p === "/ouvrir") return redirect(res, "/connexion");
      return text(res, 401, "Connexion requise");
    }
    if (p === "/page") return page(res, "pages/index.html");
    if (p === "/moi" && method === "GET")
      return json(res, 200, { id: ses.id, nom: ses.nom, admin: !!ses.admin, provisoire: ses.provisoire, secours: !!ses.secours, planning: ses.planning, flotte: ses.flotte,
        apps: Object.fromEntries(Object.entries(APPS).map(([k, a]) => [k, { nom: a.nom, pret: !!(a.url && CLE_OK) }])) });

    // Changer son propre code. Avec un code provisoire, on vient de le taper : pas besoin de le redonner.
    if (p === "/mon-code" && method === "POST") {
      if (ses.secours) return text(res, 400, "Le code de secours se change dans Vercel (CODE_ADMIN)");
      const ip = ipOf(req);
      if (await blocked(ip)) return text(res, 429, "Trop d'essais, réessaie dans quelques minutes");
      const o = await jsonBody(req, 2000) || {};
      if (!ses.provisoire) {
        const ok = (await q(`SELECT 1 FROM personnes WHERE id = $1 AND cle = $2`, [ses.id, await cleDe(o.actuel)])).rows.length;
        if (!ok) { await q(`INSERT INTO echecs (ip) VALUES ($1)`, [ip]); return text(res, 400, "Le code actuel n'est pas le bon"); }
      }
      // Un code refusé compte comme un essai : on ne peut pas tester en boucle les codes des autres.
      const err = await codeRefuse(o.code, ses.id);
      if (err) { await q(`INSERT INTO echecs (ip) VALUES ($1)`, [ip]); return text(res, 400, err); }
      await q(`UPDATE personnes SET cle = $2, provisoire = false, code_le = now() WHERE id = $1`, [ses.id, await cleDe(o.code)]);
      await log(ses.nom, `Code personnel ${ses.provisoire ? "choisi" : "changé"} par ${ses.nom}`);
      return json(res, 200, { ok: true });
    }

    // Ouverture d'une appli : le portail l'envoie avec un jeton d'une minute, l'appli ouvre sa propre session.
    if (p === "/ouvrir" && method === "GET") {
      const app = url.searchParams.get("app");
      if (!APPS[app]) return redirect(res, "/");
      if (ses.provisoire) return redirect(res, "/");
      if (ses[app] === "aucun") return redirect(res, "/?refus=" + app);
      if (!APPS[app].url || !CLE_OK) return text(res, 503, `${APPS[app].nom} n'est pas encore relié au portail : réglez ${app === "planning" ? "PLANNING_URL" : "FLOTTE_URL"} et CLE_PORTAIL dans Vercel.`);
      if (!ses.secours) await q(`UPDATE personnes SET vu = now() WHERE id = $1`, [ses.id]);
      return redirect(res, `${APPS[app].url}/api/portail?jeton=${encodeURIComponent(jetonPour(app, ses))}`);
    }

    // Page Accès : réservée aux administrateurs.
    if (p === "/personnes" || p.startsWith("/personnes/") || p === "/journal" || p === "/import-planning") {
      if (!ses.admin) return text(res, 403, "Réservé aux administrateurs");
      if (p === "/personnes" && method === "GET") return json(res, 200, (await q(`${PERSONNE} ORDER BY actif DESC, nom`)).rows);
      if (p === "/journal" && method === "GET") return json(res, 200, (await q(`SELECT t, qui, texte FROM journal ORDER BY t DESC, id DESC LIMIT 100`)).rows);
      if (p === "/personnes" && method === "POST") {
        const o = await jsonBody(req, 4000) || {};
        const nom = clean(o.nom, 40);
        if (!nom) return text(res, 400, "Indique le nom");
        const id = newId(), code = await codeProvisoire(), pl = niveau("planning", o.planning), fl = niveau("flotte", o.flotte);
        await q(`INSERT INTO personnes (id, nom, admin, cle, provisoire, planning, flotte) VALUES ($1, $2, $3, $4, true, $5, $6)`, [id, nom, !!o.admin, await cleDe(code), pl, fl]);
        await log(ses.nom, `${nom} ajouté : planning ${NIVEAU_NOM[pl]}, véhicules ${NIVEAU_NOM[fl]}${o.admin ? ", administrateur" : ""}`);
        return json(res, 200, { ok: true, id, code });
      }
      if ((m = /^\/personnes\/(p[0-9a-f]{10})(\/code)?$/.exec(p))) {
        const pr = (await q(`SELECT nom, admin, actif, planning, flotte FROM personnes WHERE id = $1`, [m[1]])).rows[0];
        if (!pr) return text(res, 404, "Personne inconnue");
        // Nouveau code provisoire : l'ancien ne marche plus, la personne choisira le sien à la prochaine connexion.
        if (m[2] && method === "POST") {
          const code = await codeProvisoire();
          await q(`UPDATE personnes SET cle = $2, provisoire = true, code_le = now() WHERE id = $1`, [m[1], await cleDe(code)]);
          await log(ses.nom, `Code de ${pr.nom} réinitialisé`);
          return json(res, 200, { ok: true, code });
        }
        if (!m[2] && method === "PUT") {
          const o = await jsonBody(req, 4000) || {};
          const moi = m[1] === ses.id;
          const v = { nom: clean(o.nom, 40) || pr.nom, admin: moi ? pr.admin : !!o.admin, actif: moi ? true : o.actif !== false,
            planning: niveau("planning", o.planning), flotte: niveau("flotte", o.flotte) };
          await q(`UPDATE personnes SET nom = $2, admin = $3, actif = $4, planning = $5, flotte = $6 WHERE id = $1`, [m[1], v.nom, v.admin, v.actif, v.planning, v.flotte]);
          if (!v.actif) await q(`UPDATE sessions SET fin = true WHERE pid = $1`, [m[1]]);
          const ch = [];
          if (v.nom !== pr.nom) ch.push(`renommé en ${v.nom}`);
          if (v.planning !== pr.planning) ch.push(`planning : ${NIVEAU_NOM[v.planning]}`);
          if (v.flotte !== pr.flotte) ch.push(`véhicules : ${NIVEAU_NOM[v.flotte]}`);
          if (v.admin !== pr.admin) ch.push(v.admin ? "devient administrateur" : "n'est plus administrateur");
          if (v.actif !== pr.actif) ch.push(v.actif ? "réactivé" : "désactivé");
          if (ch.length) await log(ses.nom, `${pr.nom} : ${ch.join(", ")}`);
          return json(res, 200, { ok: true });
        }
        // Supprimer : seulement une personne déjà désactivée, et jamais soi-même.
        if (!m[2] && method === "DELETE") {
          if (m[1] === ses.id) return text(res, 400, "Vous ne pouvez pas vous supprimer vous-même");
          if (pr.actif) return text(res, 400, "Désactivez d'abord cette personne");
          await q(`DELETE FROM sessions WHERE pid = $1`, [m[1]]);
          await q(`DELETE FROM personnes WHERE id = $1`, [m[1]]);
          await log(ses.nom, `${pr.nom} supprimé`);
          return json(res, 200, { ok: true });
        }
        return text(res, 405, "Méthode non autorisée");
      }
      // Reprise des personnes du planning avec leurs codes : chacun garde le code qu'il a déjà.
      // Possible tant que le portail est vide, ou de nouveau plus tard pour ajouter les personnes créées entre-temps dans le planning.
      if (p === "/import-planning" && method === "POST") {
        if (!APPS.planning.url || !CLE_OK) return text(res, 400, "Réglez d'abord PLANNING_URL et CLE_PORTAIL dans Vercel");
        let r;
        try {
          r = await fetch(APPS.planning.url + "/api/portail-personnes", { headers: { Authorization: "Bearer " + CLE_PORTAIL }, signal: AbortSignal.timeout(15000) });
        } catch (e) { return text(res, 502, "Planning injoignable : vérifiez PLANNING_URL"); }
        if (!r.ok) return text(res, 502, r.status === 401 || r.status === 404 ? "Le planning refuse : vérifiez que CLE_PORTAIL a la même valeur dans les deux projets, et que la mise à jour du planning est en ligne" : `Le planning répond ${r.status}`);
        const d = await r.json();
        if (!/^[0-9a-f]{64}$/.test(String(d.poivre || "")) || !Array.isArray(d.personnes)) return text(res, 502, "Réponse du planning illisible");
        const n = (await q(`SELECT count(*)::int AS n FROM personnes`)).rows[0].n;
        const actuel = (await q(`SELECT v FROM reglages WHERE k = 'poivre'`)).rows[0].v;
        if (n && actuel !== d.poivre) return text(res, 409, "Le portail a déjà des personnes ajoutées à la main : la reprise des codes du planning n'est possible que sur un portail vide. Connectez-vous avec le code de secours, désactivez puis supprimez ces personnes, et relancez la reprise");
        const client = await db().connect();
        let ajout = 0;
        try {
          await client.query("BEGIN");
          await client.query(`UPDATE reglages SET v = $1 WHERE k = 'poivre'`, [d.poivre]);
          for (const x of d.personnes.slice(0, 500)) {
            if (!/^p[0-9a-f]{10}$/.test(String(x.id)) || !/^[0-9a-f]{64}$/.test(String(x.cle))) continue;
            const ins = await client.query(`INSERT INTO personnes (id, nom, admin, actif, cle, planning, flotte) VALUES ($1, $2, $3, $4, $5, 'modif', 'aucun') ON CONFLICT DO NOTHING`,
              [x.id, clean(x.nom, 40) || "?", !!x.admin, x.actif !== false, x.cle]);
            ajout += ins.rowCount;
          }
          await client.query("COMMIT");
        } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
        poivre = d.poivre;
        await log(ses.nom, `Reprise des personnes du planning : ${ajout} ajoutée${ajout > 1 ? "s" : ""}`);
        return json(res, 200, { ok: true, ajout, total: d.personnes.length });
      }
      return text(res, 405, "Méthode non autorisée");
    }
    return text(res, 404, "Introuvable");
  } catch (e) {
    console.error(e);
    return text(res, 500, "Erreur serveur : " + String(e.message || e).slice(0, 160));
  }
}
