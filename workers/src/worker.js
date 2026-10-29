/**
 * 4DASISTAS Tab Editor Cloudflare Worker
 * 
 * Secure admin panel with session-based authentication.
 * No passwords are ever embedded in served HTML or client-side JS.
 * 
 * Endpoints:
 *   GET  /editor           - Admin editor (requires session cookie)
 *   POST /login            - Authenticate with password
 *   GET  /logout           - Destroy session
 *   GET  /api/data/:key    - Fetch data by key (public read)
 *   POST /api/data/:key    - Update data by key (requires session)
 *
 *   -- Club Members Schedule (global identity — one username can belong to several clubs) --
 *   POST   /api/login                                       - Sign in with username+PIN (no club needed), returns { ...user, clubs:[clubId,...], token }
 *   POST   /api/signup                                     - Public self-signup from the Sign Up form: {name, username, pin (4 digits), clubId}. Creates the member,
 *                                                                adds them to that ONE club (their #1 pick), and returns the same shape as /api/login (incl. token) so
 *                                                                they're signed in immediately. Optional waitlist:[clubId,...] (their 2nd/3rd picks) is stored on the user
 *                                                                and returned by /api/login + /api/signup as waitlist (auto-hidden once they're added to that club). Limits: 10/hour per IP, 100/day total; clubId must be in SIGNUP_CLUB_IDS.
 *   GET    /api/clubs/:clubId/members                       - This club's roster (name, username, photo — no PINs)
 *   GET    /api/users/:id                                   - One member's public profile
 *   PUT    /api/users/:id                                   - Update own profile photo (Bearer session token required)
 *   (Public self-signup is disabled — only the admin panel creates members, see below)
 *   GET    /api/clubs/:clubId/events                        - This club's admin-created events
 *   GET    /api/clubs/:clubId/events/:eventId/responses     - Every member's availability for one event + aggregate counts
 *   PUT    /api/clubs/:clubId/events/:eventId/responses/:userId - Save own availability for one event (Bearer session token required)
 *   GET    /api/clubs/:clubId/ideas                         - Event-idea board: [{id,title,mapUrl,date,votes,voters:[names],by,voted,mine}] (public; identity headers optional)
 *   POST   /api/clubs/:clubId/ideas                         - Add an option ({title required, mapUrl = Google Maps link optional; club-cuisine also requires cuisine}). Acting identity = signed-in member (Bearer) OR a
 *                                                                guest with just a name (X-Guest-Id + X-Guest-Name headers, no password). Creator auto-votes; max 3 per person, 40 per club
 *   POST   /api/clubs/:clubId/ideas/:ideaId/vote            - Toggle your vote (member or guest)
 *   DELETE /api/clubs/:clubId/ideas/:ideaId                 - Remove an option you added
 *   GET    /api/idea-availability                           - "Add your availability" on the idea board: your own general 15-day availability, ONE record shared across every club (not per-club) ({days:{"YYYY-MM-DD":"busy"|["morning","afternoon","evening"]}}); same identity as ideas (member Bearer token OR guest headers)
 *   PUT    /api/idea-availability                           - Replace your own general availability (same identity, same shape)
 *   GET    /api/idea-availability/all                       - Everyone's general availability, aggregated: {counts:{"YYYY-MM-DD":{morning,afternoon,evening}}, respondents, people? (names, for any signed-in requester)}; same identity gate as above
 *   PUT    /api/admin/club-ideas/:clubId/:ideaId            - Admin edits title / mapUrl / date (YYYY-MM-DD) / votes (sets the displayed total via an adjustment)
 *   DELETE /api/admin/club-ideas/:clubId/:ideaId            - Admin removes any option (session cookie)
 *   GET    /api/members                                     - Signed-in members only (Bearer token): every profile as {id, name, hasPhoto, clubs:[clubId]} (no usernames/PINs)
 *   GET    /api/members/:id                                 - Signed-in members only: one profile {id, name, photo, clubs}
 *   GET    /api/clubs/:clubId/availability/:userId          - Own month-view availability ({days:{"YYYY-MM-DD":["morning"|"afternoon"|"night"]}}); Bearer token, private to that member
 *   PUT    /api/clubs/:clubId/availability/:userId          - Replace own month-view availability ({days:{...}}); Bearer token + club membership required
 *
 *   -- Admin (session-cookie gated) --
 *   POST   /api/admin/login                                 - JSON password login for the in-site admin panel (sets the same session cookie as /login)
 *   POST   /api/admin/logout                                - JSON logout
 *   GET    /api/admin/session                                - { loggedIn }
 *   GET    /api/admin/club-members                          - All clubs' rosters (a person in several clubs appears under each)
 *   POST   /api/admin/club-members/:clubId                   - Add a member to this club — reuses an existing global username if it
 *                                                                already exists (so the same person can join another club), else
 *                                                                creates a new global identity (name, username, optional exact 4-digit pin)
 *   PUT    /api/admin/club-members/:clubId/:id                - Edit a member's name/username/pin (any subset) — edits the global identity
 *   PUT    /api/admin/users/:id/clubs                        - Set a member's full club list ({clubs:[clubId,...]}) — adds/removes as needed
 *   POST   /api/admin/club-members/:clubId/:id/reset-pin     - Issue a member a fresh random PIN
 *   DELETE /api/admin/club-members/:clubId/:id               - Remove a member from this club only (their identity/other memberships stay;
 *                                                                the global identity + username are only deleted once they're in zero clubs)
 *   GET    /api/admin/club-events/:clubId                    - This club's events (admin view)
 *   POST   /api/admin/club-events/:clubId                    - Create an event (title, desc, startDate, endDate, startHour, endHour)
 *   DELETE /api/admin/club-events/:clubId/:eventId            - Remove an event and its responses
 *
 *   -- In-site calendar event editor (session-cookie gated, commits straight to GitHub like Decap CMS) --
 *   POST   /api/admin/calendar-event                        - Create a new event ({ fields:{...} }) — derives a unique id/filename
 *                                                                from the title (mirrors Decap's slug: '{{title}}'), commits
 *                                                                data/calendar/:id.json as a new file
 *   GET    /api/admin/calendar-event/:id                     - Read one event's full source JSON from data/calendar/:id.json
 *   PUT    /api/admin/calendar-event/:id                     - Merge { fields:{...} } into that source file and commit to GitHub (main),
 *   DELETE /api/admin/calendar-event/:id                     - Delete that source JSON file from GitHub (main). The repo's rebuild
 *                                                              workflow then regenerates the aggregate data + calendar.ics without it.
 *                                                              Used by the "Needs details" review flow to drop a junk/duplicate event.
 *                                                                which triggers the existing regenerate-calendar.yml Action to rebuild
 *                                                                the aggregate data/*.json files and calendar.ics, then Cloudflare
 *                                                                auto-deploys — same pipeline Decap/DecapBridge already use.
 *   POST   /api/admin/resource                              - Create a new Resources/Small-Business listing, same pattern as above
 *                                                                but writing data/resources/:id.json
 *   GET    /api/admin/resource/:id                          - Read one listing's full source JSON
 *   PUT    /api/admin/resource/:id                          - Merge fields and commit
 *   GET    /api/admin/sitetext                              - Read data/sitetext.json (page copy, home-tile text, About page content)
 *   PUT    /api/admin/sitetext                               - Merge fields and commit
 *   GET    /api/clubs                                        - Public: the live club roster ({clubs:[...]}) - mirrored into KV on every admin write, source of
 *                                                                truth for the frontend, idea-board access, and the /clubs/:slug link-preview page below
 *   GET    /api/admin/clubs                                  - Read data/clubs.json ({items:[...]}, one file, unlike calendar/resources' per-entry files)
 *   POST   /api/admin/clubs                                  - Add a club ({fields:{title,desc,logo,signup,emoji,colour}}) - derives a unique "club-slug"
 *                                                                id + slug, appends, commits to GitHub, and mirrors the result into KV
 *   PUT    /api/admin/clubs/:id                               - Merge fields into that one club and commit. logo is only touched when the submitted
 *                                                                value is a genuinely new data: URL upload - an unchanged plain-path logo is left alone
 *   DELETE /api/admin/clubs/:id                               - Remove that club from the array and commit
 *
 * Required secrets (wrangler secret put <name>):
 *   ADMIN_PASSWORD    - admin login for /editor and the in-site Club Events / calendar-event admin panels
 *   GITHUB_TOKEN      - fine-grained GitHub PAT, Contents: Read and write, scoped to just this repo —
 *                       used only by the calendar-event editor above to commit edits
 *
 * Deploy:
 *   wrangler deploy
 */

const SESSION_TTL = 7 * 24 * 60 * 60; // 7 days in seconds
const MEMBER_SESSION_TTL = 180 * 24 * 60 * 60; // 180 days — club members stay signed in on their own device
const SUBSCRIBER_INDEX_KEY = "daily-list-subscribers";
const EVENT_FILES = ["sports", "gatherings", "dayactivities", "mosquegatherings", "trips"];

// ---- Club Members Schedule helpers ----
const CM_MAX_PHOTO_LEN = 300000; // ~225KB of raw bytes once base64-decoded
const CM_HALF_HOURS = Array.from({ length: 48 }, (_, i) => i); // 0..47, each = a 30-min slot in a day

const sha256Hex = async (input) => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
};

const randomPin = () => String(Math.floor(1000 + Math.random() * 9000));

const PHOTO_DATA_URL_RE = /^data:image\/(png|jpe?g|gif|webp);base64,[A-Za-z0-9+/]+=*$/;

const sanitizePhoto = (photo) => {
  if (!photo) return null;
  if (typeof photo !== "string" || photo.length > CM_MAX_PHOTO_LEN || !PHOTO_DATA_URL_RE.test(photo)) return null;
  return photo;
};

// New accounts get an auto-generated "firstname.initial" username (see
// generateUniqueUsername below) - but this function is also used to validate
// a *login* attempt and an admin's manual edit, and both of those have to
// keep working for accounts created under this site's older username rules
// (free-text handles, then briefly phone numbers) - changing their structure
// retroactively would just lock people out. So this stays permissive: accept
// whatever shape a username already is, only normalize case/whitespace.
const sanitizeUsername = (input) => {
  const u = String(input || "").trim().toLowerCase();
  return /^[a-z0-9._-]{2,40}$/.test(u) ? u : null;
};
const usernameBaseFromName = (name) => {
  const parts = String(name || "").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return null;
  const first = parts[0].toLowerCase().replace(/[^a-z]/g, "");
  if (!first) return null;
  const lastWord = parts.length > 1 ? parts[parts.length - 1] : "";
  const initial = lastWord.replace(/[^a-zA-Z]/g, "").slice(0, 1).toLowerCase();
  return initial ? `${first}.${initial}` : null;
};
const generateUniqueUsername = async (env, name) => {
  const base = usernameBaseFromName(name);
  if (!base) return null;
  let candidate = base;
  for (let n = 2; await findUserIdByUsername(env, candidate); n++) candidate = `${base}${n}`;
  return candidate;
};

// ---- Club roster: ONE source of truth (data/clubs.json, committed via the admin editor below),
// mirrored into KV on every write so the rest of the site can check "is this a real club?" or look up
// a club's title/slug/colour instantly, without a slow GitHub fetch and without waiting for the site's
// static index.html/worker.js to redeploy. This replaces what used to be five separate hardcoded lists
// (FALL_SIGNUP_CLUBS/CLUB_SLUGS/clubColors in index.html, SIGNUP_CLUB_IDS/CLUB_META here) that nothing
// kept in sync — deleting a club used to only edit data/clubs.json, so it silently reappeared everywhere
// else (bit Lujane twice: club-adhd, then club-theater).
const CLUB_ROSTER_KV_KEY = "clubRoster";
const CLUBS_FILE_PATH_CONST = "data/clubs.json";
// Phone / WhatsApp number: stored only on the user record and only ever returned to the admin.
const sanitizePhone = (v) => {
  const t = String(v || "").replace(/[^\d+()\-.\s]/g, "").replace(/\s+/g, " ").trim().slice(0, 25);
  const digits = t.replace(/\D/g, "");
  return digits.length >= 7 && digits.length <= 15 ? t : "";
};
const sanitizeColour = (input) => {
  const c = String(input || "").trim();
  return /^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/.test(c) ? c : "";
};
// A club committed to data/clubs.json (by the admin editor, Decap CMS or a developer) shows up in the live roster on its own:
// every ~10 minutes the Worker reads the published file and adds any club the KV roster doesn't have yet (never removes or edits one).
// Read one of the site's own published files (e.g. /data/clubs.json). The Worker can NOT fetch its own public address (that times out, HTTP 522),
// so it reads the static-assets binding, and falls back to the public GitHub copy of the same file.
const fetchSiteFile = async (env, path) => {
  try { if (env.ASSETS) { const r = await env.ASSETS.fetch(new Request("https://assets.local" + path)); if (r.ok) return r; } } catch {}
  return fetch(`https://raw.githubusercontent.com/${GITHUB_OWNER}/${GITHUB_REPO}/main${path}`, { cf: { cacheTtl: 120 } });
};
let _fileClubs = null, _fileClubsAt = 0, _rosterPutAt = 0, _fileClubsStatus = "not tried yet";
const WORKER_BUILD = "2026-10-07-d";
const loadFileClubs = async (env) => {
  if (_fileClubs && Date.now() - _fileClubsAt < 600000) return _fileClubs;
  if (!_fileClubs && Date.now() - _fileClubsAt < 30000) return []; // a failed fetch retries after 30s
  _fileClubsAt = Date.now();
  try {
    const res = await fetchSiteFile(env, "/data/clubs.json");
    if (!res.ok) { _fileClubsStatus = `fetch failed: HTTP ${res.status}`; console.warn("club file fetch failed", res.status); return _fileClubs || []; }
    const items = (await res.json()).items;
    if (Array.isArray(items)) { _fileClubs = items.filter((c) => c && c.id && c.title); _fileClubsStatus = `ok (${_fileClubs.length} clubs in the file)`; }
    else _fileClubsStatus = "file had no items array";
  } catch (e) { _fileClubsStatus = `fetch error: ${String(e).slice(0, 120)}`; console.warn("club file fetch error", String(e)); }
  return _fileClubs || [];
};
// Deleted clubs are remembered ("tombstones") so the file sync can NEVER bring one back — before this, deleting a club re-created it a few
// minutes later because a cached copy of clubs.json still listed it (bit Lujane with M&M). DELETED_CLUB_SEED covers clubs deleted before tombstones existed.
const DELETED_CLUBS_KV_KEY = "deletedClubs";
const DELETED_CLUB_SEED = ["club-mm"];
const readDeletedClubs = async (env) => {
  let arr = [];
  try { const raw = await env.SITE_DATA.get(DELETED_CLUBS_KV_KEY); if (raw) { const a = JSON.parse(raw); if (Array.isArray(a)) arr = a; } } catch {}
  return new Set(DELETED_CLUB_SEED.concat(arr).filter((x) => typeof x === "string"));
};
const setClubDeleted = async (env, id, deleted) => {
  let arr = [];
  try { const raw = await env.SITE_DATA.get(DELETED_CLUBS_KV_KEY); if (raw) { const a = JSON.parse(raw); if (Array.isArray(a)) arr = a; } } catch {}
  arr = arr.filter((x) => x !== id);
  if (deleted) arr.push(id);
  await env.SITE_DATA.put(DELETED_CLUBS_KV_KEY, JSON.stringify(arr));
  _fileClubs = null; _fileClubsAt = 0; // forget the cached copy of clubs.json
};
// The merged result is returned (and cached in memory) even if saving it to KV fails, so a new club always shows up.
const syncRosterFromFile = async (env, roster) => {
  const file = await loadFileClubs(env);
  const have = new Set(roster.map((c) => c.id));
  let missing = file.filter((c) => !have.has(c.id));
  const hasDeleted = roster.some((c) => DELETED_CLUB_SEED.includes(c.id));
  if (!missing.length && !hasDeleted) return roster;
  const gone = await readDeletedClubs(env);
  missing = missing.filter((c) => !gone.has(c.id));
  const kept = roster.filter((c) => !gone.has(c.id));
  if (!missing.length && kept.length === roster.length) return roster;
  const merged = kept.concat(missing);
  if (kept.length !== roster.length || Date.now() - _rosterPutAt > 600000) { _rosterPutAt = Date.now(); try { await env.SITE_DATA.put(CLUB_ROSTER_KV_KEY, JSON.stringify(merged)); } catch (e) { _fileClubsStatus += `; saving to KV failed: ${String(e).slice(0, 80)}`; console.warn("roster save failed", String(e)); } }
  return merged;
};
const readClubRoster = async (env) => {
  const raw = await env.SITE_DATA.get(CLUB_ROSTER_KV_KEY);
  if (raw) { try { const arr = JSON.parse(raw); if (Array.isArray(arr)) return await syncRosterFromFile(env, arr); } catch {} }
  // First run since this feature shipped, or KV got cleared: seed from the committed file.
  const file = await githubGetFile(env, CLUBS_FILE_PATH_CONST).catch(() => null);
  const clubs = file && Array.isArray(file.content?.items) ? file.content.items : [];
  if (clubs.length) await env.SITE_DATA.put(CLUB_ROSTER_KV_KEY, JSON.stringify(clubs)).catch(() => {});
  return clubs;
};
const writeClubRoster = async (env, roster) => env.SITE_DATA.put(CLUB_ROSTER_KV_KEY, JSON.stringify(roster));
const isKnownClubId = async (env, clubId) => (await readClubRoster(env)).some((c) => c.id === clubId);
const SIGNUP_MAX_PER_IP_PER_HOUR = 10;
const SIGNUP_MAX_PER_DAY = 100;
const LOGIN_MAX_ATTEMPTS_PER_IP_PER_HOUR = 20;
const LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_HOUR = 10;

// ---- Global member identity: one person, one username, can belong to several clubs ----
const userKey = (userId) => `user:${userId}`;

// ---- D1 (SQLite): profiles + availability live here once a D1 database is attached (binding `DB`) AND the one-time migration has run
// (admin page → Team → "Move to D1"). D1's free plan allows 5M reads / 100k writes per day and has no list limit, unlike KV (1k lists/writes).
// Until then — or if no database is attached — everything keeps working on KV exactly as before.
let _d1Ready = null, _d1Mode = { at: 0, on: false };
const d1Ensure = async (env) => {
  if (!env.DB) return false;
  if (!_d1Ready) _d1Ready = env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT, username TEXT, data TEXT NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS ideaavail (person_id TEXT PRIMARY KEY, data TEXT NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)"),
  ]).catch((e) => { _d1Ready = null; throw e; });
  await _d1Ready;
  return true;
};
const d1On = async (env) => {
  if (!env.DB) return false;
  if (_d1Mode.on) return true;
  if (Date.now() - _d1Mode.at < 20000) return false;
  try { await d1Ensure(env); const r = await env.DB.prepare("SELECT v FROM meta WHERE k = 'migrated'").first(); _d1Mode = { at: Date.now(), on: !!(r && r.v === "1") }; }
  catch { _d1Mode = { at: Date.now(), on: false }; }
  return _d1Mode.on;
};
const readUser = async (env, userId) => {
  if (await d1On(env)) { const r = await env.DB.prepare("SELECT data FROM users WHERE id = ?").bind(userId).first(); return r ? JSON.parse(r.data) : null; }
  const raw = await env.SITE_DATA.get(userKey(userId));
  return raw ? JSON.parse(raw) : null;
};

// ---- ID indexes. Cloudflare's free plan allows only 1,000 KV *list* calls a day; once that's used up every list fails and whole pages
// (the availability grid, the admin profile list) go dark. So hot paths read ONE index doc with a plain GET instead of listing.
// An index is built from a list exactly once (the first time it's missing) and then kept up to date as people are created/deleted.
const USER_INDEX_KEY = "idx:users";
const IA_INDEX_KEY = "idx:ideaavail";
const readIndex = async (env, key) => { try { const a = JSON.parse((await env.SITE_DATA.get(key)) || "null"); return Array.isArray(a) ? a : null; } catch { return null; } };
const addToIndex = async (env, key, id) => { const ids = await readIndex(env, key); if (!ids || ids.includes(id)) return; ids.push(id); await env.SITE_DATA.put(key, JSON.stringify(ids)); };
const removeFromIndex = async (env, key, id) => { const ids = await readIndex(env, key); if (!ids || !ids.includes(id)) return; await env.SITE_DATA.put(key, JSON.stringify(ids.filter((x) => x !== id))); };
// If a list is impossible right now (quota used up), fall back to everyone who is in a club — read with plain GETs only.
const idsFromClubMembers = async (env) => { const s = new Set(); for (const c of await clubIdList(env)) for (const id of await readClubMemberIds(env, c)) s.add(id); return [...s]; };
const allUserIds = async (env) => {
  let ids = await readIndex(env, USER_INDEX_KEY);
  if (ids) return ids;
  try {
    ids = []; let cursor;
    do { const page = await env.SITE_DATA.list({ prefix: "user:", cursor }); for (const k of page.keys) ids.push(k.name.slice(5)); cursor = page.list_complete ? undefined : page.cursor; } while (cursor);
    await env.SITE_DATA.put(USER_INDEX_KEY, JSON.stringify(ids)).catch(() => {});
    return ids;
  } catch (e) { return await idsFromClubMembers(env); } // not saved: the real index is built the next time a list works
};
// Every profile (full records). D1: one query. KV: ids from the index, then one GET each.
const listAllUsers = async (env) => {
  if (await d1On(env)) return ((await env.DB.prepare("SELECT data FROM users").all()).results || []).map((r) => JSON.parse(r.data));
  const out = [];
  for (const id of await allUserIds(env)) { const u = await readUser(env, id); if (u) out.push(u); }
  return out;
};
const readIaDoc = async (env, personId) => {
  if (await d1On(env)) { const r = await env.DB.prepare("SELECT data FROM ideaavail WHERE person_id = ?").bind(personId).first(); return r ? r.data : null; }
  return env.SITE_DATA.get(ideaAvailKey(personId));
};
const writeIaDoc = async (env, personId, rawJson) => {
  if (await d1On(env)) { await env.DB.prepare("INSERT OR REPLACE INTO ideaavail (person_id, data) VALUES (?, ?)").bind(personId, rawJson).run(); return; }
  await env.SITE_DATA.put(ideaAvailKey(personId), rawJson);
  await addToIndex(env, IA_INDEX_KEY, personId).catch(() => {});
};
const deleteIaDoc = async (env, personId) => {
  if (await d1On(env)) { await env.DB.prepare("DELETE FROM ideaavail WHERE person_id = ?").bind(personId).run(); return; }
  await env.SITE_DATA.delete(ideaAvailKey(personId));
};
const _userIdxSeen = new Set();
// Last-known-good copies, used only if a live read fails (e.g. a Cloudflare quota is hit) so pages degrade instead of going blank.
const readSnapshot = async (env, key) => { try { return JSON.parse((await env.SITE_DATA.get(key)) || "null"); } catch { return null; } };
const _snapAt = {};
const saveSnapshot = async (env, key, data) => { if (Date.now() - (_snapAt[key] || 0) < 600000) return; _snapAt[key] = Date.now(); try { await env.SITE_DATA.put(key, JSON.stringify({ at: Date.now(), data })); } catch {} };

const writeUser = async (env, user) => {
  { const d = bmDigits(user.phone); if (d.length >= 7 && user.phoneIdx !== d) { await phoneIndexAdd(env, d, user.id); user.phoneIdx = d; } }
  if (await d1On(env)) { await env.DB.prepare("INSERT OR REPLACE INTO users (id, name, username, data) VALUES (?, ?, ?, ?)").bind(user.id, user.name || "", user.username || "", JSON.stringify(user)).run(); return; }
  await env.SITE_DATA.put(userKey(user.id), JSON.stringify(user), { metadata: { name: user.name, hasPhoto: !!user.photo } });
  if (!_userIdxSeen.has(user.id)) { _userIdxSeen.add(user.id); try { await addToIndex(env, USER_INDEX_KEY, user.id); } catch {} }
};

const deleteUser = async (env, userId) => {
  if (await d1On(env)) { await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run(); return; }
  await env.SITE_DATA.delete(userKey(userId));
  _userIdxSeen.delete(userId);
  try { await removeFromIndex(env, USER_INDEX_KEY, userId); } catch {}
};

const visibleWaitlist = (user, clubs) => (Array.isArray(user.waitlist) ? user.waitlist : []).filter((id) => !clubs.includes(id));
const publicUser = (u) => ({ id: u.id, name: u.name, username: u.username, photo: u.photo || null, mustChangePin: !!u.mustChangePin });

// ---- Club membership: each club just holds a list of member userIds ----
const clubMembersKey = (clubId) => `clubmembers:${clubId}`;

const readClubMemberIds = async (env, clubId) => {
  const raw = await env.SITE_DATA.get(clubMembersKey(clubId));
  return raw ? JSON.parse(raw) : [];
};

const writeClubMemberIds = async (env, clubId, ids) => {
  await env.SITE_DATA.put(clubMembersKey(clubId), JSON.stringify(ids));
};

const resolveClubMembers = async (env, clubId) => {
  const ids = await readClubMemberIds(env, clubId);
  const users = await Promise.all(ids.map(id => readUser(env, id)));
  return users.filter(Boolean);
};

// KV *list* calls are the scarcest free-tier resource (1,000/day), so hot paths use direct gets over the club roster instead of listing keys.
const clubIdList = async (env) => {
  try { const r = await readClubRoster(env); const ids = r.map((c) => c.id).filter(Boolean); if (ids.length) return ids; } catch {}
  return (await env.SITE_DATA.list({ prefix: "clubmembers:" })).keys.map((k) => k.name.slice("clubmembers:".length));
};
const DEFAULT_AVAIL_PERIOD = { start: "2026-10-08", end: "2026-10-20" };
const readAvailPeriodKV = async (env) => {
  try { const p = JSON.parse((await env.SITE_DATA.get("availperiod")) || "null"); if (p && /^\d{4}-\d{2}-\d{2}$/.test(p.start) && /^\d{4}-\d{2}-\d{2}$/.test(p.end) && p.end >= p.start) return { start: p.start, end: p.end }; } catch {}
  return DEFAULT_AVAIL_PERIOD;
};
const availPeriodDates = (period, includePast) => {
  const out = [], today = new Date().toISOString().slice(0, 10);
  const d = new Date(period.start + "T12:00:00Z"), end = new Date(period.end + "T12:00:00Z");
  for (let i = 0; i < 60 && d <= end; i++) { const k = d.toISOString().slice(0, 10); if (includePast || k >= today) out.push(k); d.setUTCDate(d.getUTCDate() + 1); }
  return out;
};
// Every availability period that has been opened (newest first): the saved history + the current one + the very first default.
const listAvailPeriods = async (env) => {
  let hist = []; try { const a = JSON.parse((await env.SITE_DATA.get("availperiods")) || "[]"); if (Array.isArray(a)) hist = a; } catch {}
  const cur = await readAvailPeriodKV(env);
  let hidden = []; try { const a = JSON.parse((await env.SITE_DATA.get("availperiodsHidden")) || "[]"); if (Array.isArray(a)) hidden = a; } catch {}
  for (const per of [cur, DEFAULT_AVAIL_PERIOD]) if (!hist.some((h) => h.start === per.start && h.end === per.end) && !(hidden.includes(`${per.start}_${per.end}`) && per !== cur)) hist.push({ start: per.start, end: per.end, at: 0 });
  hist.sort((a, b) => b.start.localeCompare(a.start));
  return { current: cur, periods: hist };
};
const allClubIdsContaining = async (env, userId) => {
  const out = [];
  for (const clubId of await clubIdList(env)) if ((await readClubMemberIds(env, clubId)).includes(userId)) out.push(clubId);
  return out;
};

// ---- Club join requests: nobody is added to a club just by asking - an admin approves. One KV key per
// (club, person) so two people requesting at the same moment can't overwrite each other's request. ----
const joinReqKey = (clubId, userId) => `joinreq:${clubId}:${userId}`;
const listJoinRequests = async (env) => {
  const list = await env.SITE_DATA.list({ prefix: "joinreq:" });
  const out = [];
  for (const k of list.keys) {
    const [, clubId, userId] = k.name.split(":");
    let at = 0;
    try { at = JSON.parse((await env.SITE_DATA.get(k.name)) || "{}").at || 0; } catch {}
    out.push({ clubId, userId, at });
  }
  return out;
};
const pendingClubIdsFor = async (env, userId) => {
  const out = [];
  for (const clubId of await clubIdList(env)) if (await env.SITE_DATA.get(joinReqKey(clubId, userId))) out.push(clubId);
  return out;
};
const JOIN_REQUESTS_MAX_PENDING_PER_PERSON = 4;
// Emails the admin each time someone asks to join a club. Needs the ADMIN_NOTIFY_EMAIL secret; if it isn't
// set (or Resend isn't), the request is still saved and shows up in the admin panel - it just can't email.
const EVENT_SUGGESTION_MAX_PENDING = 300;
const EVENT_GENRES = ["sports", "activities", "functions", "trips", "knowledge", "other"];
// genre -> the Calendar tab it most likely belongs under (the review page preselects this; she can change it)
const GENRE_TO_SECTION = { sports: "sports", activities: "activities", functions: "functions", trips: "trips", knowledge: "mosqueprograms", other: "functions" };
const EVENT_SUGGESTION_MAX_PER_IP_PER_HOUR = 5;
// ---- Signed review links: the notification email links to a review page where Lujane can edit, accept or deny
// without logging in. The link carries an HMAC of (kind, id) keyed off the admin password, so it can't be guessed
// or reused for another submission. The page itself only ever acts on an explicit button press (never on a GET),
// so email link-scanners that pre-open links can't accept/deny anything.
const hmacHex = async (secret, message) => {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
};
const reviewSig = (env, kind, id) => hmacHex(`review-link:${env.ADMIN_PASSWORD || ""}`, `${kind}:${id}`);
const sameSig = (a, b) => { a = String(a || ""); b = String(b || ""); if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const reviewUrlFor = async (env, kind, id, action) => `${env.SITE_ORIGIN || "https://4dasistas.ca"}/review/${kind}/${encodeURIComponent(id)}?sig=${await reviewSig(env, kind, id)}${action ? `&a=${action}` : ""}`;
// Every email goes through here. With env.__capture (the admin's email preview) nothing is sent — the message is just collected.
const postResend = (env, payload) => env.__capture
  ? (env.__capture.push(payload), Promise.resolve(new Response("{}", { status: 200 })))
  : fetch("https://api.resend.com/emails", { method: "POST", headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify(payload) });
// ---- Email theme: the same look as the website (cream page, rose header, brown outlines, rounded pills).
const emailBtn = (href, label, bg = "#ce8491", color = "#fff") => `<a href="${escapeHtml(href)}" style="display:inline-block;margin:4px 6px 4px 0;padding:12px 20px;border-radius:999px;background:${bg};color:${color};border:2px solid #76220b;font-weight:700;text-decoration:none;font-size:15px;font-family:Arial,Helvetica,sans-serif">${label}</a>`;
const emailRow = (label, value) => `<tr><td style="padding:7px 14px 7px 0;color:#776867;font-size:12px;text-transform:uppercase;letter-spacing:.6px;vertical-align:top;white-space:nowrap">${label}</td><td style="padding:7px 0;vertical-align:top;color:#373d3b"><strong>${value}</strong></td></tr>`;
const emailChip = (text) => `<span style="display:inline-block;padding:3px 12px;border-radius:999px;background:#f2d8d7;color:#76220b;border:1.5px solid #ce8491;font-size:13px;font-weight:700">${text}</span>`;
const emailNote = (html) => `<div style="margin:12px 0;padding:12px 14px;border-radius:14px;background:#fef7f4;border:2px solid #f2d8d7;color:#76220b;font-size:14px">${html}</div>`;
const emailShell = (env, { title, emoji = "✨", preheader = "", body = "", footer = "" }) => {
  const origin = env.SITE_ORIGIN || "https://4dasistas.ca";
  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#fef7f4">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">${escapeHtml(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#fef7f4"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px">
<tr><td style="background:#ce8491;border:2px solid #76220b;border-radius:20px 20px 0 0;padding:20px 22px;text-align:center"><a href="${origin}" style="text-decoration:none"><span style="font-family:Georgia,'Times New Roman',serif;font-size:30px;letter-spacing:4px;font-weight:700;color:#ffffff">4DASISTAS</span></a><div style="font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#fde9ea;letter-spacing:1.6px;margin-top:3px">CLUBS · EVENTS · SQUADS · GTA</div></td></tr>
<tr><td style="background:#ffffff;border:2px solid #76220b;border-top:0;border-radius:0 0 20px 20px;padding:24px 22px;font-family:Arial,Helvetica,sans-serif;color:#373d3b;font-size:15px;line-height:1.55">
<div style="font-size:28px;line-height:1">${emoji}</div>
<h2 style="margin:6px 0 12px;font-size:22px;line-height:1.25;color:#76220b">${title}</h2>
${body}
${footer ? `<div style="margin-top:18px;padding-top:14px;border-top:2px dashed #f2d8d7;font-size:12px;color:#776867">${footer}</div>` : ""}
</td></tr>
<tr><td align="center" style="padding:14px 8px;font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#9a8c8a">Sent with 💗 from <a href="${origin}" style="color:#9a8c8a">4dasistas.ca</a></td></tr>
</table></td></tr></table></body></html>`;
};
// What someone put on the sign-up form (clubs they ranked, comments, whether they'd lead). Shown to the admin on their profile.
const sanitizeSignupForm = (f, source) => {
  if (!f || typeof f !== "object") return null;
  const clean = (v, n) => String(v == null ? "" : v).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, " ").trim().slice(0, n);
  const ranked = (Array.isArray(f.ranked) ? f.ranked : []).map((x) => clean(x, 40)).filter(Boolean).slice(0, 6);
  const form = { ranked, other: clean(f.other, 60), why: clean(f.why, 1500), lead: clean(f.lead, 30), at: Number(f.at) > 0 ? Number(f.at) : Date.now(), source: source || "site" };
  return (ranked.length || form.why || form.other) ? form : null;
};
// ---- BACKUPS: the WHOLE project, in one email.
//  1) a JSON data file with everything that lives in Cloudflare and can't be rebuilt from GitHub: profiles (incl. PIN hashes), availability, club + squad
//     membership, join/squad requests, event + resource submissions, club admins, idea boards (votes), club events + responses, push subscriptions,
//     newsletter subscribers and every setting;
//  2) the site's code + data files (index.html, the Worker, data/*.json, assets...) as a zip of the public GitHub repo, attached by link.
// Emailed once a day by the cron (de-duplicated — see claimBackupSlot) and on demand from the admin page. Private data: keep the email private.
const buildBackup = async (env) => {
  const warnings = [];
  const safe = async (label, fn, fallback) => { try { return await fn(); } catch (e) { warnings.push(`${label}: ${String(e && e.message || e).slice(0, 120)}`); return fallback; } };
  const users = await listAllUsers(env);
  const availability = {};
  await safe("availability", async () => {
    if (await d1On(env)) { for (const r of ((await env.DB.prepare("SELECT person_id, data FROM ideaavail").all()).results || [])) availability[r.person_id] = r.data; }
    else { for (const pid of [...users.map((u) => `m:${u.id}`), "admin"]) { const raw = await env.SITE_DATA.get(ideaAvailKey(pid)); if (raw) availability[pid] = raw; } }
  });
  const clubIds = await clubIdList(env);
  const clubMembers = {}, ideas = {}, clubEvents = {}, clubEventResponses = {};
  for (const c of clubIds) {
    clubMembers[c] = await safe(`members ${c}`, () => readClubMemberIds(env, c), []);
    ideas[c] = await safe(`ideas ${c}`, () => env.SITE_DATA.get(clubIdeasKey(c)), null);
    const evRaw = await safe(`events ${c}`, () => env.SITE_DATA.get(clubEventsKey(c)), null);
    if (evRaw) { clubEvents[c] = evRaw; try { for (const ev of JSON.parse(evRaw)) { const r = await env.SITE_DATA.get(clubEventResponsesKey(c, ev.id)); if (r) clubEventResponses[`${c}:${ev.id}`] = r; } } catch {} }
  }
  const calForms = {};
  await safe("club calendar forms", async () => { for (const e of await readClubCal(env)) if (e.form) { const r = await env.SITE_DATA.get(calFormKey(e.id)); if (r) calForms[e.id] = r; } });
  const squads = {};
  for (const sid of Object.keys(SQUAD_TITLES)) squads[sid] = { members: await safe(`squad ${sid}`, () => readSquadMemberIds(env, sid), []), link: (await safe(`squadlink ${sid}`, () => env.SITE_DATA.get(squadLinkKey(sid)), "")) || "" };
  const steps = { daily: [], pledges: [] }; // steps challenge (D1): last 120 days of daily totals + every pledge
  await safe("steps", async () => { if (await stepsEnsure(env)) { const cut = new Date(Date.now() - 120 * 86400000).toISOString().slice(0, 10); steps.daily = (await env.DB.prepare("SELECT user_id, day, steps, source FROM steps_daily WHERE day >= ? ORDER BY day").bind(cut).all()).results || []; steps.pledges = (await env.DB.prepare("SELECT id, round_id, name, user_id, per1000, cap, at FROM step_pledges").all()).results || []; } });
  const dump = async (prefix) => { const out = {}; for (const k of (await env.SITE_DATA.list({ prefix })).keys) { const v = await env.SITE_DATA.get(k.name); if (v) out[k.name] = v; } return out; };
  const joinRequests = await safe("join requests", () => dump("joinreq:"), {});
  const squadRequests = await safe("squad requests", () => dump("squadreq:"), {});
  const eventSubmissions = await safe("event submissions", () => dump("eventsug:"), {});
  const resourceSubmissions = await safe("resource submissions", () => dump("ressug:"), {});
  const clubAdmins = await safe("club admins", () => dump("clublead:"), {});
  const pushSubscriptions = {};
  for (const u of users) { const raw = await safe(`push ${u.id}`, () => env.SITE_DATA.get(pushKey(u.id)), null); if (raw) pushSubscriptions[u.id] = raw; }
  const settings = {};
  for (const k of ["clubRoster", "clubcal", "labels", "evsubform", "availperiod", "availperiods", "availperiodsHidden", "watemplates", "steprounds", SUBSCRIBER_INDEX_KEY]) settings[k] = await safe(`setting ${k}`, () => env.SITE_DATA.get(k), null);
  const counts = { users: users.length, availability: Object.keys(availability).length, clubs: clubIds.length, joinRequests: Object.keys(joinRequests).length, squadRequests: Object.keys(squadRequests).length, eventSubmissions: Object.keys(eventSubmissions).length, resourceSubmissions: Object.keys(resourceSubmissions).length, clubAdmins: Object.keys(clubAdmins).length };
  return { version: 2, at: new Date().toISOString(), storage: (await d1On(env)) ? "d1" : "kv", counts, warnings, users, availability, clubMembers, ideas, clubEvents, clubEventResponses, calForms, squads, steps, joinRequests, squadRequests, eventSubmissions, resourceSubmissions, clubAdmins, pushSubscriptions, settings };
};
// The daily cron fired twice a few seconds apart (two near-identical emails). Whoever claims today's slot first sends; the other stops.
// D1 gives an atomic "first one wins" (INSERT OR IGNORE); without D1 it falls back to a best-effort KV marker.
const claimBackupSlot = async (env, prefix) => {
  const key = `${prefix || "backup"}:${new Date().toISOString().slice(0, 10)}`; // one claim per day per job — the cron can fire more than once
  try {
    if (env.DB) { await d1Ensure(env); const r = await env.DB.prepare("INSERT OR IGNORE INTO meta (k, v) VALUES (?, ?)").bind(key, String(Date.now())).run(); return !!(r.meta && r.meta.changes > 0); }
  } catch {}
  if (await env.SITE_DATA.get(key)) return false;
  await env.SITE_DATA.put(key, String(Date.now()), { expirationTtl: 172800 }).catch(() => {});
  return true;
};
const sendBackupEmail = async (env, label) => {
  if (!env.RESEND_API_KEY || !env.ADMIN_NOTIFY_EMAIL) return { ok: false, error: "Email isn't set up" };
  const b = await buildBackup(env);
  const json = JSON.stringify(b);
  const bytes = new TextEncoder().encode(json); let bin = ""; for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const day = b.at.slice(0, 10), c = b.counts;
  const send = (withCode) => postResend(env, {
    from: env.FROM_EMAIL || "4DASISTAS <updates@4dasistas.ca>", to: [env.ADMIN_NOTIFY_EMAIL], subject: `4DASISTAS full backup ${day} (${c.users} profiles)`,
      html: emailShell(env, { emoji: "🛟", title: label || "Daily backup", preheader: `${c.users} profiles · ${c.clubs} clubs · everything saved`,
        body: `<p style="margin:0 0 10px"><strong>Everything for the project, as of ${escapeHtml(b.at.slice(0, 16).replace("T", " "))} UTC.</strong></p>
          <div style="margin:0 0 10px;padding:12px 14px;border-radius:14px;background:#fef7f4;border:2px solid #f2d8d7"><div style="font-weight:700;color:#76220b">📄 ${escapeHtml(`4dasistas-data-${day}.json`)}</div><div style="font-size:13px;color:#555;margin-top:2px">${c.users} profiles (with PIN hashes), ${c.availability} availability records, ${c.clubs} clubs and members, idea boards &amp; votes, club events, squads, ${c.joinRequests} join + ${c.squadRequests} squad requests, ${c.eventSubmissions} event + ${c.resourceSubmissions} resource submissions, ${c.clubAdmins} club admins, push subscriptions, newsletter list and all settings.</div></div>
          <div style="margin:0 0 10px;padding:12px 14px;border-radius:14px;background:#fef7f4;border:2px solid #f2d8d7"><div style="font-weight:700;color:#76220b">🗜️ ${withCode ? escapeHtml(`4dasistas-site-${day}.zip`) : "Website zip not attached"}</div><div style="font-size:13px;color:#555;margin-top:2px">${withCode ? "The whole website — pages, the Worker code, calendar / resource / club data and images, straight from GitHub." : "It couldn't be attached this time — the code is always safe on GitHub (github.com/lujaneyaffa/4dasistas)."}</div></div>
          ${b.warnings.length ? `<p style="color:#b3261e;font-size:13px">Some parts could not be read: ${escapeHtml(b.warnings.join("; "))}</p>` : ""}`,
        footer: "🔒 <strong>Keep this email private</strong> — it contains names, phone numbers and PIN hashes. If anything is ever lost, send these files to Claude and everything can be restored." }),
      attachments: [{ filename: `4dasistas-data-${day}.json`, content: btoa(bin) }].concat(withCode ? [{ filename: `4dasistas-site-${day}.zip`, path: `https://codeload.github.com/${GITHUB_OWNER}/${GITHUB_REPO}/zip/refs/heads/main` }] : []),
  });
  let r = await send(true);
  if (!r.ok) r = await send(false); // never lose the data backup just because the code zip couldn't be fetched
  return r.ok ? { ok: true, users: c.users } : { ok: false, error: `Email failed (${r.status})` };
};
const digestEmailHtml = (env, dateString, events, unsubscribeUrl, manageUrl) => {
  const origin = env.SITE_ORIGIN || "https://4dasistas.ca";
  const list = events.map((item) => `<div style="margin:0 0 10px;padding:12px 14px;border-radius:14px;background:#fef7f4;border:2px solid #f2d8d7"><div style="font-weight:700;color:#76220b;font-size:16px">${escapeHtml(item.title)}</div><div style="font-size:13px;color:#555;margin-top:2px">🕒 ${escapeHtml(item.date || "Today")} &nbsp;·&nbsp; 📍 ${escapeHtml(item.location || "Location TBA")}</div></div>`).join("");
  return emailShell(env, { emoji: "☀️", title: "What's on today", preheader: `${events.length} thing${events.length === 1 ? "" : "s"} happening today`, body: `<p style="margin:0 0 14px;color:#776867">${escapeHtml(dateString)}</p>${list}<p style="margin:16px 0 4px">${emailBtn(origin + "/", "See the full calendar →")}${manageUrl ? emailBtn(manageUrl, "⚙️ Manage subscription", "#fff", "#76220b") : ""}</p>`, footer: `You're receiving this because you subscribed to the 4DASISTAS daily list. <a href="${manageUrl || unsubscribeUrl}" style="color:#776867">Manage</a> · <a href="${unsubscribeUrl}" style="color:#776867">Unsubscribe</a>` });
};
const sendAdminEmail = (env, ctx, subject, html) => {
  if (!env.RESEND_API_KEY || !env.ADMIN_NOTIFY_EMAIL) return;
  ctx.waitUntil(postResend(env, { from: env.FROM_EMAIL || "4DASISTAS <updates@4dasistas.ca>", to: [env.ADMIN_NOTIFY_EMAIL], subject, html })
    .then(async (r) => { if (!r.ok) console.error("Resend rejected admin notification", r.status, (await r.text()).slice(0, 300)); }).catch((e) => console.error("Resend request failed", String(e))));
};
const notifyAdminOfSuggestion = async (env, ctx, kind, sug) => {
  if (!env.RESEND_API_KEY || !env.ADMIN_NOTIFY_EMAIL) return;
  const isEvent = kind === "event";
  const rows = isEvent
    ? (sug.extra || []).map((x) => emailRow(escapeHtml(x.label), escapeHtml(x.value))).join("") + emailRow("Event", escapeHtml(sug.name)) + emailRow("Date", escapeHtml(sug.date)) + emailRow("Genre", escapeHtml(sug.genre === "other" ? `Other: ${sug.genreOther || ""}` : (sug.genre || "—"))) + emailRow("City", escapeHtml(sug.city)) + emailRow("Link", `<a href="${escapeHtml(sug.link)}">${escapeHtml(sug.link)}</a>`)
    : emailRow("Name", escapeHtml(sug.title)) + emailRow("Type", escapeHtml(sug.type === "other" ? `Other: ${sug.typeOther || ""}` : sug.type)) + emailRow("City", escapeHtml(sug.city)) + emailRow("Link", `<a href="${escapeHtml(sug.link)}">${escapeHtml(sug.link)}</a>`);
  const comments = sug.comments ? emailNote(`<div style="font-size:12px;opacity:.8;margin-bottom:2px">💬 Comments from the submitter</div>${escapeHtml(sug.comments).replace(/\n/g, "<br>")}`) : "";
  const html = emailShell(env, {
    emoji: isEvent ? "🗓️" : "🛍️", title: `New ${isEvent ? "event" : "resource"} submitted`, preheader: isEvent ? `${sug.name} · ${sug.city} · ${sug.date}` : `${sug.title} · ${sug.city}`,
    body: `<table style="border-collapse:collapse;font-size:15px">${rows}</table>${comments}<p style="margin:16px 0 4px">${emailBtn(await reviewUrlFor(env, kind, sug.id, "accept"), "✅ Accept", "#2a7a4a")}${emailBtn(await reviewUrlFor(env, kind, sug.id, "edit"), "✏️ Edit", "#ce8491")}${emailBtn(await reviewUrlFor(env, kind, sug.id, "deny"), "❌ Deny", "#b3261e")}</p>`,
    footer: `Each button opens a review page — nothing happens until you confirm there. You can also find it on your admin page under <strong>Notifications</strong>.` });
  sendAdminEmail(env, ctx, isEvent ? `Event submitted: ${sug.name} (${sug.city}, ${sug.date})` : `Resource submitted: ${sug.title} (${sug.city})`, html);
};
// Email the admin when someone signs up through an event form (new sign-ups only, not edits).
const notifyAdminOfFormSignup = (env, ctx, ev, person, answers, sel) => {
  if (!env.RESEND_API_KEY || !env.ADMIN_NOTIFY_EMAIL) return;
  const origin = env.SITE_ORIGIN || "https://4dasistas.ca";
  const form = ev.form || { fields: [] }, pay = form.payment || {};
  const val = (v) => Array.isArray(v) ? v.join(", ") : (v && typeof v === "object" ? String(v.address || "") : String(v));
  const rows = emailRow("Event", `${escapeHtml(ev.title)} · ${escapeHtml(ev.date)}`)
    + emailRow("Name", escapeHtml(person.name) + (person.newAccount ? ' <span style="color:#2a7a4a">(new account)</span>' : ""))
    + (person.phone ? emailRow("Phone", escapeHtml(person.phone)) : "")
    + (person.contact ? emailRow("Contact", escapeHtml(person.contact)) : "")
    + (sel && sel.ids && sel.ids.length ? emailRow("Add-ons", escapeHtml((pay.addons || []).filter((a) => sel.ids.includes(a.id)).map((a) => a.label).join(", "))) : "")
    + (sel && sel.total != null ? emailRow("Total due", `<strong>${escapeHtml(String(sel.total))}</strong>`) : "")
    + (form.fields || []).filter((f) => answers && answers[f.id] !== undefined).map((f) => emailRow(escapeHtml(calPlain(f.label)), escapeHtml(val(answers[f.id])))).join("");
  const html = emailShell(env, { emoji: "📝", title: "New event sign-up", preheader: `${person.name} → ${ev.title}`,
    body: `<table style="border-collapse:collapse;font-size:15px">${rows}</table><p style="margin:16px 0 4px">${emailBtn(`${origin}/#/admin`, "Open Club Events →")}</p>`,
    footer: "See everyone's answers, mark people paid and download a CSV under Admin → Club Events → 📋 Answers." });
  sendAdminEmail(env, ctx, `Sign-up: ${person.name} → ${ev.title}`, html);
};
const notifyAdminOfEventSuggestion = (env, ctx, sug) => notifyAdminOfSuggestion(env, ctx, "event", sug);
const notifyAdminOfResourceSuggestion = (env, ctx, sug) => notifyAdminOfSuggestion(env, ctx, "resource", sug);
// ---- Web Push (free phone notifications). A push with NO payload wakes the member's service worker, which then fetches
// the message text from /api/push/message and shows it (so no payload encryption is needed). Auth is VAPID: a short
// ES256 JWT signed with VAPID_PRIVATE_JWK (Worker secret); the matching public key is below + in index.html.
const VAPID_PUBLIC_KEY = "BEMVhYcg0NJP_6Z_-T_ZOqyeFFG0ZN7aNVhqO_lykhIbwX9B7IDGYkwfGfPPR-GyJsaSfU0Ewbezmlzzt6xwqXs";
const b64urlBytes = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlText = (text) => b64urlBytes(new TextEncoder().encode(text));
const pushKey = (userId) => `push:${userId}`;
const readPushSubs = async (env, userId) => { try { return JSON.parse((await env.SITE_DATA.get(pushKey(userId))) || "[]"); } catch { return []; } };
const endpointHash = (endpoint) => sha256Hex(endpoint);
const vapidAuthHeader = async (env, endpoint) => {
  const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const aud = new URL(endpoint).origin;
  const head = b64urlText(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const claims = b64urlText(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "mailto:admin@4dasistas.ca" }));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(`${head}.${claims}`));
  return `vapid t=${head}.${claims}.${b64urlBytes(sig)}, k=${VAPID_PUBLIC_KEY}`;
};
// Send one notification to every device a member registered. Returns { sent, removed, devices }.
// Members choose which kinds of notification they get (Settings → Notifications); `message.cat` is the kind.
// ---- Public, privacy-minimal member info: FIRST NAME ONLY + an opaque id (never the user id / username / phone) ----
const pubId = async (env, uid) => (await sha256Hex(`${uid}:pub:${env.ADMIN_PASSWORD || "4ds"}`)).slice(0, 16);
// Public lists never show a full username: the LAST THREE characters are replaced by ***  (alice.a → alic***).
// Public lists show a person as "First L." (first name + first letter of the last name) — never the username.
const pubName = (name, fallback) => { const parts = String(name || "").trim().split(/\s+/).filter(Boolean); if (!parts.length) return String(fallback || "Member"); const f = parts[0].slice(0, 20); return parts.length > 1 ? f + " " + parts[parts.length - 1][0].toUpperCase() + "." : f; };
const maskPublic = (n) => { const t = String(n || "").trim(); return t.length > 3 ? t.slice(0, -3) + "***" : "***"; };
const firstNameOnly = (n) => String(n || "").trim().split(/\s+/)[0].slice(0, 30) || "Member";
// A brand-new member created from an event FORM (the base fields every form asks logged-out people for: name, phone, a 4-digit PIN).
const createMemberFromForm = async (env, ctx, ip, input) => {
  const clean = (v, n) => String(v || "").replace(/[\u0000-\u001f\u007f]/g, "").replace(/\s+/g, " ").trim().slice(0, n);
  const name = clean(input.name, 60), pin = String(input.pin || "").trim(), phone = sanitizePhone(input.phone);
  if (!name) return { status: 400, error: "Please enter your name" };
  const username = await generateUniqueUsername(env, name);
  if (!username) return { status: 400, error: "Please enter your first name and last name (or initial)" };
  if (!/^\d{4}$/.test(pin)) return { status: 400, error: "Your PIN must be exactly 4 digits" };
  if (!phone) return { status: 400, error: "Please add your phone / WhatsApp number" };
  if (username !== usernameBaseFromName(name)) {
    const norm = (n) => String(n || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if ((await listAllUsers(env)).some((u) => norm(u.name) === norm(name))) return { status: 409, error: `There's already a profile for ${name}. Tap “Already a member?” above, find yourself and enter your PIN.` };
  }
  const ipKey = `signuprate:${ip}:${Math.floor(Date.now() / 3600000)}`, dayKey = `signupday:${new Date().toISOString().slice(0, 10)}`;
  const [ipCount, dayCount] = await Promise.all([env.SITE_DATA.get(ipKey), env.SITE_DATA.get(dayKey)]);
  if (Number(ipCount || 0) >= SIGNUP_MAX_PER_IP_PER_HOUR) return { status: 429, error: "Too many sign-ups from this connection — please try again in an hour" };
  if (Number(dayCount || 0) >= SIGNUP_MAX_PER_DAY) return { status: 429, error: "Sign-ups are very busy right now — please message us on Instagram" };
  if (await findUserIdByUsername(env, username)) return { status: 409, error: "That login was just taken — please try again" };
  const user = { id: crypto.randomUUID(), name, username, pinHash: await sha256Hex(pin), photo: null, waitlist: [], createdAt: Date.now(), phone };
  user.lastLoginAt = user.createdAt; user.lastSeenAt = user.createdAt;
  { // the shortened sign-up questions (clubs they're interested in, anything they'd like us to know) are kept on their profile like the full sign-up form's
    const roster = await readClubRoster(env);
    const titles = (Array.isArray(input.interests) ? input.interests : []).map(String).map((id) => (roster.find((c) => c.id === id) || {}).title).filter(Boolean);
    const sf = sanitizeSignupForm({ ranked: titles, why: input.why }, "form"); if (sf) user.form = sf;
  }
  await writeUser(env, user);
  await reserveUsername(env, username, user.id);
  _memberSearchCache = null; // so they can be found right away
  await Promise.all([env.SITE_DATA.put(ipKey, String(Number(ipCount || 0) + 1), { expirationTtl: 3700 }), env.SITE_DATA.put(dayKey, String(Number(dayCount || 0) + 1), { expirationTtl: 90000 })]);
  // (no separate 'new member' email: the event sign-up email says '(new account)')
  return { user, token: await createMemberSession(env, user.id) };
};
// People search (to sign in from a form): first name + last initial only, ≥3 letters, rate-limited, cached.
let _memberSearchCache = null;
const NOTIF_CATS = ["reminders", "announcements", "clubs", "events", "steps", "badminton"];
// ---- Apple push (APNs) for the native iPhone app. Needs secrets APNS_KEY (the .p8 text), APNS_KEY_ID, APNS_TEAM_ID. The app's bundle id is the "topic". ----
const APNS_TOPIC = "4DS";
const _apnsJwt = { production: { at: 0, jwt: "" }, sandbox: { at: 0, jwt: "" } };
// Apple issued two keys: APNS_KEY(+_ID) works on the SANDBOX gateway (builds installed from Xcode), APNS_KEY_PROD(+_ID_PROD) on PRODUCTION (TestFlight / App Store). A single "Sandbox & Production" key would serve both.
const apnsAuth = async (env, which) => {
  const cache = _apnsJwt[which], keyPem = which === "production" ? (env.APNS_KEY_PROD || env.APNS_KEY) : env.APNS_KEY, keyId = which === "production" ? (env.APNS_KEY_ID_PROD || env.APNS_KEY_ID) : env.APNS_KEY_ID;
  if (cache.jwt && Date.now() - cache.at < 45 * 60000) return cache.jwt;
  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const enc = (o) => b64u(new TextEncoder().encode(JSON.stringify(o)));
  const pem = String(keyPem || "").replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const head = enc({ alg: "ES256", kid: keyId }), body = enc({ iss: env.APNS_TEAM_ID, iat: Math.floor(Date.now() / 1000) });
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(`${head}.${body}`));
  _apnsJwt[which] = { at: Date.now(), jwt: `${head}.${body}.${b64u(sig)}` };
  return _apnsJwt[which].jwt;
};
// Sends one notification to every iPhone registered for this person. Tries production first, then the sandbox (a build installed from Xcode registers a sandbox token).
const sendApns = async (env, userId, message) => {
  if (!env.APNS_KEY || !env.APNS_KEY_ID || !env.APNS_TEAM_ID || !env.DB) return { sent: 0, devices: 0 };
  let tokens = []; try { await seenEnsure(env); tokens = (await env.DB.prepare("SELECT token FROM device_tokens WHERE user_id = ?").bind(userId).all()).results || []; } catch { return { sent: 0, devices: 0 }; }
  let sent = 0, badge = 1;
  try { const r = await env.DB.prepare("INSERT INTO badge_counts (user_id, n) VALUES (?, 1) ON CONFLICT(user_id) DO UPDATE SET n = n + 1 RETURNING n").bind(userId).first(); if (r && r.n) badge = r.n; } catch {} // the number on the app icon = unread notifications
  for (const t of tokens) {
    const payload = JSON.stringify({ aps: { alert: { title: message.title || "4DS", body: message.body || "" }, sound: "default", badge }, url: message.url || "/" });
    let done = false;
    for (const host of ["api.push.apple.com", "api.sandbox.push.apple.com"]) {
      const jwt = await apnsAuth(env, host.includes("sandbox") ? "sandbox" : "production").catch(() => "");
      if (!jwt) continue;
      try {
        const res = await fetch(`https://${host}/3/device/${t.token}`, { method: "POST", headers: { authorization: `bearer ${jwt}`, "apns-topic": APNS_TOPIC, "apns-push-type": "alert", "apns-priority": "10" }, body: payload });
        if (res.ok) { sent++; done = true; break; }
        const txt = await res.text().catch(() => ""), reason = (() => { try { return JSON.parse(txt).reason; } catch { return ""; } })();
        if (res.status === 410 || reason === "Unregistered") { await env.DB.prepare("DELETE FROM device_tokens WHERE token = ?").bind(t.token).run(); done = true; break; }
        if (reason !== "BadDeviceToken" && reason !== "DeviceTokenNotForTopic" && reason !== "BadEnvironmentKeyInToken") { console.error("APNs rejected", host, res.status, reason); done = true; break; } // (BadDeviceToken = wrong environment: try the other)
      } catch (e) { console.error("APNs failed", String(e)); done = true; break; }
    }
  }
  return { sent, devices: tokens.length };
};
const sendPushToUser = async (env, userId, message) => {
  if (message.cat) { const u = await readUser(env, userId); if (u && Array.isArray(u.notifOff) && u.notifOff.includes(message.cat)) return { sent: 0, removed: 0, devices: 0, muted: true }; }
  const ap = await sendApns(env, userId, message);
  const subs = await readPushSubs(env, userId);
  if (!subs.length || !env.VAPID_PRIVATE_JWK) return { sent: ap.sent, removed: 0, devices: subs.length + ap.devices };
  let sent = ap.sent; const keep = [];
  for (const sub of subs) {
    try {
      await env.SITE_DATA.put(`pushmsg:${await endpointHash(sub.endpoint)}`, JSON.stringify({ title: message.title, body: message.body, url: message.url || "/", at: Date.now() }), { expirationTtl: 86400 });
      const res = await fetch(sub.endpoint, { method: "POST", headers: { Authorization: await vapidAuthHeader(env, sub.endpoint), TTL: "86400", Urgency: "normal", "Content-Length": "0" } });
      if (res.status === 404 || res.status === 410) continue; // the device unsubscribed / app removed: drop it
      keep.push(sub);
      if (res.ok) sent++; else console.error("Push rejected", res.status, (await res.text().catch(() => "")).slice(0, 160));
    } catch (e) { keep.push(sub); console.error("Push failed", String(e)); }
  }
  if (keep.length !== subs.length) await env.SITE_DATA.put(pushKey(userId), JSON.stringify(keep));
  return { sent, removed: subs.length - keep.length, devices: subs.length + ap.devices };
};
// ---- Steps challenge: biweekly rounds, per-person daily steps (synced from Apple Health / Health Connect by the native app), per-1,000-step pledges for a charity. ----
// Daily rows live in D1 (free plan: 100k writes/day) — an hourly sync per person would blow through KV's 1k writes/day. Rounds are one small KV doc.
let _stepsReady = null;
const stepsEnsure = async (env) => {
  if (!env.DB) return false;
  if (!_stepsReady) _stepsReady = env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS steps_daily (user_id TEXT NOT NULL, day TEXT NOT NULL, steps INTEGER NOT NULL, source TEXT, updated INTEGER, PRIMARY KEY (user_id, day))"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS steps_day ON steps_daily (day)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS step_pledges (id TEXT PRIMARY KEY, round_id TEXT NOT NULL, name TEXT, user_id TEXT, per1000 REAL NOT NULL, cap REAL, at INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS step_participants (round_id TEXT NOT NULL, user_id TEXT NOT NULL, at INTEGER, added INTEGER DEFAULT 0, PRIMARY KEY (round_id, user_id))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS step_sources (user_id TEXT PRIMARY KEY, source TEXT, at INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS step_diag (user_id TEXT PRIMARY KEY, at INTEGER, ok INTEGER, msg TEXT)"),
  ]).then(() => env.DB.prepare("ALTER TABLE step_sources ADD COLUMN goal INTEGER").run().catch(() => {})).catch((e) => { _stepsReady = null; throw e; });
  await _stepsReady;
  return true;
};
// The last thing that happened when this person's steps tried to sync (shown to them and to the admin, so a silent failure is never invisible).
const stepDiag = async (env, userId, ok, msg) => { try { await env.DB.prepare("INSERT INTO step_diag (user_id, at, ok, msg) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET at = excluded.at, ok = excluded.ok, msg = excluded.msg").bind(userId, Date.now(), ok ? 1 : 0, String(msg || "").slice(0, 240)).run(); } catch {} };
const STEP_ROUNDS_KEY = "steprounds", STEP_MAX_PER_DAY = 60000;
// ---- Google Health (the cloud account behind Fitbit / Pixel Watch / Google Health app): works on any phone, even an iPhone. OAuth 2.0 + the Google Health API; the owner sets the Worker secrets GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET. ----
let _ghReady = null;
const ghEnsure = async (env) => {
  if (!env.DB || !env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) return false;
  if (!_ghReady) _ghReady = env.DB.prepare("CREATE TABLE IF NOT EXISTS gh_tokens (user_id TEXT PRIMARY KEY, access TEXT, refresh TEXT, exp INTEGER, at INTEGER)").run().catch((e) => { _ghReady = null; throw e; });
  await _ghReady;
  return true;
};
const ghRedirect = (env) => `${env.SITE_ORIGIN || "https://4dasistas.ca"}/api/google/callback`;
const ghToken = async (env, params) => {
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, ...params }).toString() });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error(j.error_description || j.error || "Google said no");
  return j;
};
// Pull the last few days of steps (whole-day totals) from the Google Health API into steps_daily.
const ghSync = async (env, userId) => {
  if (!(await ghEnsure(env)) || !(await stepsEnsure(env))) return 0;
  let row = await env.DB.prepare("SELECT access, refresh, exp FROM gh_tokens WHERE user_id = ?").bind(userId).first();
  if (!row) return 0;
  if (row.exp < Date.now() + 60000) {
    let j; try { j = await ghToken(env, { grant_type: "refresh_token", refresh_token: row.refresh }); }
    catch (e) { // Google refused the saved login (expired / revoked — apps in Google's "Testing" mode get 7-day logins): forget it so the member is asked to reconnect
      await env.DB.prepare("DELETE FROM gh_tokens WHERE user_id = ?").bind(userId).run().catch(() => {});
      await stepDiag(env, userId, false, "Google Health needs reconnecting (" + String((e && e.message) || e).slice(0, 120) + ")");
      throw new Error("Google Health needs reconnecting — tap Connect Google Health"); }
    row = { access: j.access_token, refresh: j.refresh_token || row.refresh, exp: Date.now() + (j.expires_in || 3600) * 1000 };
    await env.DB.prepare("UPDATE gh_tokens SET access = ?, refresh = ?, exp = ?, at = ? WHERE user_id = ?").bind(row.access, row.refresh, row.exp, Date.now(), userId).run();
  }
  const today = new Date(), start = new Date(Date.now() - 14 * 86400000), end = new Date(Date.now() + 86400000);
  const civ = (d) => ({ date: { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1, day: d.getUTCDate() }, time: { hours: 0, minutes: 0, seconds: 0, nanos: 0 } });
  const r = await fetch("https://health.googleapis.com/v4/users/me/dataTypes/steps/dataPoints:dailyRollUp", { method: "POST", headers: { Authorization: "Bearer " + row.access, "Content-Type": "application/json" }, body: JSON.stringify({ range: { start: civ(start), end: civ(end) }, windowSizeDays: 1, pageSize: 20 }) });
  if (!r.ok) { await stepDiag(env, userId, false, "Google Health error " + r.status); const bt = (await r.text().catch(() => "")).slice(0, 400); throw new Error("Couldn't read Google Health steps (" + r.status + ") " + bt.replace(/\s+/g, " ").slice(0, 220)); }
  const j = await r.json(), stmts = [], now = Date.now();
  for (const x of j.rollupDataPoints || []) {
    const c = (x.civilStartTime || {}).date || {}; if (!c.year) continue;
    const day = `${c.year}-${String(c.month).padStart(2, "0")}-${String(c.day).padStart(2, "0")}`;
    const s = x.steps || {}; let steps = NaN; for (const k of Object.keys(s)) { const v = Number(s[k]); if (/count|sum|steps/i.test(k) && Number.isFinite(v)) { steps = Math.round(v); break; } }
    if (isValidDateString(day) && Number.isFinite(steps) && steps >= 0) stmts.push(env.DB.prepare("INSERT INTO steps_daily (user_id, day, steps, source, updated) VALUES (?, ?, ?, 'googlehealth', ?) ON CONFLICT(user_id, day) DO UPDATE SET steps = excluded.steps, source = excluded.source, updated = excluded.updated").bind(userId, day, Math.min(steps, STEP_MAX_PER_DAY), now));
  }
  if (stmts.length) await env.DB.batch(stmts);
  await stepDiag(env, userId, true, stmts.length ? "Synced " + stmts.length + " days from Google Health" : "Google Health had no steps for the last few days");
  _stepsPublicMemo = { at: 0, data: null }; // the challenge totals at the top must include these numbers right away
  return stmts.length;
};
const readStepRounds = async (env) => { try { const a = JSON.parse((await env.SITE_DATA.get(STEP_ROUNDS_KEY)) || "[]"); return Array.isArray(a) ? a : []; } catch { return []; } };
const cleanStepRound = (r) => {
  if (!r || !isValidDateString(r.start) || !isValidDateString(r.end) || r.end < r.start) return null;
  let url = ""; try { const u = new URL(String(r.charityUrl || "").trim()); if (u.protocol === "https:") url = u.href.slice(0, 500); } catch {}
  return { id: /^[a-z0-9-]{3,40}$/.test(String(r.id || "")) ? String(r.id) : crypto.randomUUID().slice(0, 8), title: cleanCalText(r.title, 80) || "Steps round", start: r.start, end: r.end,
    charity: cleanCalText(r.charity, 100), charityUrl: url, goal: Math.max(0, Math.min(100000000, Math.round(Number(r.goal) || 0))),
    description: String(r.description || "").replace(/[\x00-\x08\x0b-\x1f\x7f<>]/g, " ").trim().slice(0, 800), mode: r.mode === "invite" ? "invite" : "open" };
};
// The round happening now; else the next one coming up; else the most recent finished one.
const currentStepRound = (rounds, today) => rounds.find((r) => r.start <= today && today <= r.end) || rounds.filter((r) => r.start > today).sort((a, b) => a.start.localeCompare(b.start))[0] || rounds.slice().sort((a, b) => b.end.localeCompare(a.end))[0] || null;
const stepRoundTotals = async (env, round) => {
  const t = await env.DB.prepare("SELECT COALESCE(SUM(d.steps),0) AS s, COUNT(DISTINCT d.user_id) AS p FROM steps_daily d JOIN step_participants q ON q.user_id = d.user_id AND q.round_id = ? WHERE d.day BETWEEN ? AND ?").bind(round.id, round.start, round.end).first();
  const joined = await env.DB.prepare("SELECT COUNT(*) AS n FROM step_participants WHERE round_id = ?").bind(round.id).first();
  const steps = (t && t.s) || 0, people = (t && t.p) || 0;
  const pl = (await env.DB.prepare("SELECT per1000, cap FROM step_pledges WHERE round_id = ?").bind(round.id).all()).results || [];
  let raised = 0; for (const x of pl) { const v = (x.per1000 * steps) / 1000; raised += x.cap ? Math.min(x.cap, v) : v; }
  return { steps, people, participants: (joined && joined.n) || 0, raised: Math.round(raised * 100) / 100, pledges: pl.length };
};
let _stepsPublicMemo = { at: 0, data: null };
const stepsPublicData = async (env) => {
  if (_stepsPublicMemo.data && Date.now() - _stepsPublicMemo.at < 60000) return _stepsPublicMemo.data;
  const rounds = (await readStepRounds(env)).sort((a, b) => b.start.localeCompare(a.start)), today = new Date().toISOString().slice(0, 10);
  const cur = currentStepRound(rounds, today);
  const data = { round: cur ? { id: cur.id, title: cur.title, description: cur.description || "", mode: cur.mode || "open", start: cur.start, end: cur.end, charity: cur.charity, charityUrl: cur.charityUrl, goal: cur.goal, status: cur.end < today ? "finished" : cur.start > today ? "upcoming" : "live", ...(await stepRoundTotals(env, cur)) } : null, previous: [] };
  for (const r of rounds.filter((x) => cur && x.id !== cur.id && x.end < today).slice(0, 6)) data.previous.push({ title: r.title, start: r.start, end: r.end, charity: r.charity, ...(await stepRoundTotals(env, r)) });
  _stepsPublicMemo = { at: Date.now(), data };
  return data;
};
// ---- Badminton (merged in from the old Supabase "ladies-badminton" site). Rows are stored as the original JSON so the points logic ports unchanged; `uid` links a player to a 4DS account. ----
// phone digits -> username (memoised ~10 min; refreshed at most once a minute on a miss). "ambiguous" when two accounts share a number.
// PHONE INDEX: KV `phoneidx:<last-10-digits>` -> [user ids]. Logging in by phone used to scan EVERY account (17 s); now it's two reads. Kept up to date by writeUser; rebuilt by the daily cron / on first use.
let _phoneMap = { at: 0, map: null }; // (legacy memo reset — harmless)
const phoneIdxKey = (d) => `phoneidx:${d}`;
const phoneIndexAdd = async (env, digits, userId) => {
  try { const cur = JSON.parse((await env.SITE_DATA.get(phoneIdxKey(digits))) || "[]"); const list = Array.isArray(cur) ? cur : []; if (!list.includes(userId)) { list.push(userId); await env.SITE_DATA.put(phoneIdxKey(digits), JSON.stringify(list.slice(-5))); } } catch {}
};
const rebuildPhoneIndex = async (env) => {
  let n = 0; for (const u of await listAllUsers(env)) { const d = bmDigits(u.phone); if (d.length >= 7) { await phoneIndexAdd(env, d, u.id); n++; } }
  await env.SITE_DATA.put("phoneidx:built", String(Date.now())); return n;
};
const usernameForPhone = async (env, digits, ctx) => {
  const raw = await env.SITE_DATA.get(phoneIdxKey(digits));
  if (!raw) { // not indexed: if the index was never built, build it in the background (the next try works)
    if (ctx && !(await env.SITE_DATA.get("phoneidx:built"))) ctx.waitUntil(rebuildPhoneIndex(env).catch(() => {}));
    return "";
  }
  let ids = []; try { ids = JSON.parse(raw); } catch {}
  const hits = []; for (const id of ids) { const u = await readUser(env, id); if (u && bmDigits(u.phone) === digits && u.username && !hits.includes(u.username)) hits.push(u.username); }
  return hits.length === 1 ? hits[0] : hits.length > 1 ? "ambiguous" : "";
};
const BM_TABLES = { players: "bm_players", games: "bm_games", attendance: "bm_attendance", past_points: "bm_past", session_rsvps: "bm_rsvps", tournament_interest: "bm_interest" };
let _bmReady = null;
const bmEnsure = async (env) => {
  if (!env.DB) return false;
  if (!_bmReady) _bmReady = env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS bm_players (id TEXT PRIMARY KEY, uid TEXT, data TEXT NOT NULL)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS bm_players_uid ON bm_players (uid)"),
    ...["bm_games", "bm_attendance", "bm_past", "bm_rsvps", "bm_interest"].map((t) => env.DB.prepare(`CREATE TABLE IF NOT EXISTS ${t} (id TEXT PRIMARY KEY, day TEXT, data TEXT NOT NULL)`)),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS bm_meta (k TEXT PRIMARY KEY, v TEXT)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS bm_files (path TEXT PRIMARY KEY, ctype TEXT, b64 TEXT NOT NULL, at INTEGER)"),
  ]).catch((e) => { _bmReady = null; throw e; });
  await _bmReady;
  return true;
};
// ---- Badminton compatibility layer: the ORIGINAL badminton app runs on 4DS (public/badminton.html + bm-shim.js, a stand-in for the Supabase client).
// Tables hold the original JSON rows; this layer re-creates the old row-level rules (owner / coach / member / iPad kiosk). ----
const isAdminRequest = async (env, request) => {
  const m = (request.headers.get("Cookie") || "").match(/(?:^|;\s*)session=([^;]+)/), tok = m ? m[1] : null;
  if (!tok) return false;
  const raw = await env.SITE_DATA.get(`session:${tok}`); if (!raw) return false;
  try { const sess = JSON.parse(raw); return !(sess.expiresAt && Date.now() > sess.expiresAt); } catch { return false; }
};
// A 4DS CLUB ADMIN of the Badminton club is the badminton coach too (same account, no separate login).
const bmLeadIsCoach = async (env, request) => {
  const m = (request.headers.get("Cookie") || "").match(/(?:^|;\s*)leadsession=([^;]+)/); if (!m) return false;
  try {
    const sess = JSON.parse((await env.SITE_DATA.get(`leadsession:${m[1]}`)) || "null"); if (!sess || (sess.expiresAt && Date.now() > sess.expiresAt)) return false;
    const rec = JSON.parse((await env.SITE_DATA.get(`clublead:${sess.username}`)) || "null"); return !!rec && Array.isArray(rec.clubs) && rec.clubs.includes("club-badminton");
  } catch { return false; }
};
// ---- matching old badminton players to 4DS accounts (by name + phone), and merging duplicate players ----
const bmLetters = (t) => String(t || "").toLowerCase().normalize("NFKD").replace(/[^a-z\s]/g, " ").replace(/\s+/g, " ").trim();
const bmParts = (name) => { const t = bmLetters(name).split(" ").filter(Boolean); return { first: t[0] || "", last: t.length > 1 ? t[t.length - 1] : "" }; };
// 0..1.5: first names must agree; last name full match / same initial adds; a shared phone number (last 7 digits) is decisive.
const bmScore = (a, b, phoneA, phoneB) => {
  const x = bmParts(a), y = bmParts(b); let sc = 0;
  const pa = bmDigits(phoneA).slice(-7), pb = bmDigits(phoneB).slice(-7);
  if (pa.length === 7 && pa === pb) sc += 1;
  if (x.first && x.first === y.first) { sc += 0.5; if (x.last && y.last) { if (x.last === y.last) sc += 0.5; else if (x.last[0] === y.last[0] && (x.last.length === 1 || y.last.length === 1)) sc += 0.4; else sc -= 0.2; } } // (a different last name is only a weak hint — e.g. a maiden name — so same-first-name accounts are still offered, never pre-selected)
  return sc;
};
const bmMerge = async (env, keepId, dropId) => {
  const rows = await bmLoadRows(env, "players", true), keep = rows.find((r) => r.id === keepId), drop = rows.find((r) => r.id === dropId);
  if (!keep || !drop || keepId === dropId) return false;
  const kn = keep.row.full_name || keep.row.name, idents = new Set([drop.row.id, drop.row.name, drop.row.nickname, drop.row.full_name].filter(Boolean).map(String));
  const stmts = [];
  for (const g of await bmLoadRows(env, "games", true)) {
    let changed = false; const row = { ...g.row };
    for (const f of ["winners", "losers"]) {
      let arr = Array.isArray(row[f]) ? row[f] : (() => { try { const j = JSON.parse(row[f]); return Array.isArray(j) ? j : null; } catch { return null; } })(); if (!arr) continue;
      const mapped = arr.map((v) => idents.has(String(v)) ? (String(v) === String(drop.row.id) ? keep.row.id : kn) : v);
      const uniq = mapped.filter((v, i) => mapped.indexOf(v) === i); if (JSON.stringify(uniq) !== JSON.stringify(arr)) { row[f] = typeof g.row[f] === "string" ? JSON.stringify(uniq) : uniq; changed = true; }
    }
    if (changed) stmts.push(bmSaveStmt(env, "games", g.id, row, null));
  }
  const seen = new Set();
  for (const key of ["attendance", "past_points", "session_rsvps", "tournament_interest"]) for (const r of await bmLoadRows(env, key, true)) {
    if (r.row.player_id !== drop.row.id && r.row.player_id !== keep.row.id) continue;
    const moved = { ...r.row, player_id: keep.row.id, ...(r.row.username && drop.row.username && r.row.username === drop.row.username ? { username: keep.row.username } : {}) };
    const dk = `${key}|${moved.player_id}|${moved.session_date || ""}|${moved.week_number || ""}${key === "past_points" ? "|" + (moved.points || 0) : ""}`;
    if (seen.has(dk) && key !== "past_points") { stmts.push(env.DB.prepare(`DELETE FROM ${BM_TBL[key]} WHERE id = ?`).bind(r.id)); continue; }
    seen.add(dk); if (r.row.player_id === drop.row.id) stmts.push(bmSaveStmt(env, key, r.id, moved, null));
  }
  const merged = { ...drop.row, ...keep.row };
  for (const k of ["avatar_url", "level", "phone", "username", "nickname"]) if (!keep.row[k] && drop.row[k]) merged[k] = drop.row[k];
  if (drop.row.date_joined && (!keep.row.date_joined || drop.row.date_joined < keep.row.date_joined)) merged.date_joined = drop.row.date_joined;
  merged.id = keep.row.id;
  stmts.push(bmSaveStmt(env, "players", keep.id, merged, keep.uid || drop.uid || null), env.DB.prepare("DELETE FROM bm_players WHERE id = ?").bind(drop.id));
  for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
  return true;
};
// A voted-on IDEA (the vote bubble on the calendar) and the real EVENT it turned into are the same activity: same day, same club, similar name ("Go karting" ≈ "Go-Karting Night").
const actWords = (t) => String(t || "").toLowerCase().normalize("NFKD").replace(/[^a-z\s]/g, " ").split(/\s+/).filter((w) => w.length >= 3 && !["the", "and", "night", "day", "club", "event", "trip", "activity", "evening", "meet", "meetup", "hangout", "for", "our", "at"].includes(w));
const sameActivity = (a, b) => {
  const x = actWords(a), y = actWords(b); if (!x.length || !y.length) return false;
  const jx = x.join(""), jy = y.join(""); if (jx === jy || jx.includes(jy) || jy.includes(jx)) return true; // "go karting" vs "gokarting"
  return x.some((w) => w.length >= 4 && y.some((v) => v.length >= 4 && (v.includes(w) || w.includes(v) || (w.length >= 5 && v.length >= 5 && w.slice(0, 4) === v.slice(0, 4))))); // ("karting" ≈ "karts")
};
// Delete a person and everything tied to their account (used by "Delete my account" in the app; Apple requires it).
const eraseUserEverywhere = async (env, user) => {
  const userId = user.id;
  for (const clubId of await clubIdList(env)) { const ids = await readClubMemberIds(env, clubId); if (ids.includes(userId)) await writeClubMemberIds(env, clubId, ids.filter((id) => id !== userId)); }
  for (const k of (await env.SITE_DATA.list({ prefix: "joinreq:" })).keys) if (k.name.split(":")[2] === userId) await env.SITE_DATA.delete(k.name);
  await deleteIaDoc(env, `m:${userId}`); _ideaAvailMemo = { at: 0, people: null };
  await env.SITE_DATA.delete(pushKey(userId));
  for (const sid of Object.keys(SQUAD_TITLES)) { await writeSquadMemberIds(env, sid, (await readSquadMemberIds(env, sid)).filter((x) => x !== userId)); await env.SITE_DATA.delete(squadReqKey(sid, userId)); }
  try { // club events: RSVPs, interest and their form answers
    const cal = await readClubCal(env); let changed = false;
    for (const e of cal) { const n = (e.rsvps || []).length, i = (e.interest || []).length; e.rsvps = (e.rsvps || []).filter((r) => r.id !== userId); if (e.interest) e.interest = e.interest.filter((x) => x.id !== userId); if (e.rsvps.length !== n || (e.interest || []).length !== i) changed = true;
      if (e.form) { const raw = await env.SITE_DATA.get(calFormKey(e.id)); if (raw) { const m = JSON.parse(raw); if (m[userId]) { delete m[userId]; await env.SITE_DATA.put(calFormKey(e.id), JSON.stringify(m)); } } } }
    if (changed) await writeClubCal(env, cal);
  } catch {}
  if (env.DB) { try { // steps + badminton: their step rows and pledges go; their badminton games stay as an anonymous "Former player" so other people's scores don't change
    await stepsEnsure(env); await env.DB.batch([env.DB.prepare("DELETE FROM steps_daily WHERE user_id = ?").bind(userId), env.DB.prepare("DELETE FROM step_pledges WHERE user_id = ?").bind(userId)]);
    await bmEnsure(env); const pr = await env.DB.prepare("SELECT id, data FROM bm_players WHERE uid = ?").bind(userId).first();
    if (pr) { const d = JSON.parse(pr.data); await env.DB.prepare("UPDATE bm_players SET uid = NULL, data = ? WHERE id = ?").bind(JSON.stringify({ id: d.id, name: "Former player", full_name: "Former player", level: d.level || null, active: false, date_joined: d.date_joined || "" }), pr.id).run(); }
  } catch {} }
  const dg = bmDigits(user.phone); if (dg.length >= 7) { try { const cur = JSON.parse((await env.SITE_DATA.get(phoneIdxKey(dg))) || "[]").filter((x) => x !== userId); await env.SITE_DATA.put(phoneIdxKey(dg), JSON.stringify(cur)); } catch {} }
  await releaseUsername(env, user.username);
  await deleteUser(env, userId); // their login stops working because the user no longer exists
};
// ---- KV WRITES ARE THE SCARCE THING (free plan: 1,000/day). "Last seen", login time and login-attempt counters used to be KV writes on every visit/login; they now live in D1 (100k writes/day). ----
let _seenReady = null;
const seenEnsure = async (env) => {
  if (!env.DB) return false;
  if (!_seenReady) _seenReady = env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS member_seen (user_id TEXT PRIMARY KEY, login_at INTEGER, seen_at INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS rate_limits (k TEXT PRIMARY KEY, n INTEGER NOT NULL, exp INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS device_tokens (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, platform TEXT, at INTEGER)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS device_tokens_user ON device_tokens (user_id)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS badge_counts (user_id TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)"),
  ]).catch((e) => { _seenReady = null; throw e; });
  await _seenReady; return true;
};
const _touched = new Map();
const touchMember = async (env, userId, login) => {
  try {
    if (!(await seenEnsure(env))) return false;
    if (!login && Date.now() - (_touched.get(userId) || 0) < 600000) return true; // at most every 10 min per person per server instance
    _touched.set(userId, Date.now()); const now = Date.now();
    await env.DB.prepare("INSERT INTO member_seen (user_id, login_at, seen_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET seen_at = excluded.seen_at" + (login ? ", login_at = excluded.login_at" : "")).bind(userId, login ? now : 0, now).run();
    return true;
  } catch { return false; }
};
const seenMap = async (env) => { const m = new Map(); try { if (await seenEnsure(env)) for (const r of (await env.DB.prepare("SELECT user_id, login_at, seen_at FROM member_seen").all()).results || []) m.set(r.user_id, { login: r.login_at || 0, seen: r.seen_at || 0 }); } catch {} return m; };
const seenOf = (m, u) => ({ lastLoginAt: Math.max(u.lastLoginAt || 0, (m.get(u.id) || {}).login || 0), lastSeenAt: Math.max(u.lastSeenAt || 0, (m.get(u.id) || {}).seen || 0) });
// attempt counters: returns the NEW count for this key (D1), or null when D1 isn't available
const rateTouch = async (env, key, ttlSec) => { try { if (!(await seenEnsure(env))) return null; const r = await env.DB.prepare("INSERT INTO rate_limits (k, n, exp) VALUES (?, 1, ?) ON CONFLICT(k) DO UPDATE SET n = CASE WHEN exp < ? THEN 1 ELSE n + 1 END, exp = CASE WHEN exp < ? THEN excluded.exp ELSE exp END RETURNING n").bind(key, Date.now() + ttlSec * 1000, Date.now(), Date.now()).first(); return r ? r.n : null; } catch { return null; } };
// The four former squads are community groups (WhatsApp chat + events), NOT idea/vote/availability clubs: they never count towards who's "waiting to vote" or whose availability is shown.
const COMMUNITY_CLUBS = new Set(["club-quran", "club-badminton", "club-cowork", "club-steps"]);
const BM_OWNER_ID = "a517d9bd-bc9c-4e59-b36d-503747621aa4", BM_COACH_EMAIL = "coach@4dasistas.ca", BM_BADMINTON_CLUB = "club-badminton";
const BM_TBL = { players: "bm_players", games: "bm_games", attendance: "bm_attendance", past_points: "bm_past", session_rsvps: "bm_rsvps", tournament_interest: "bm_interest" };
const bmToronto = (d = new Date()) => d.toLocaleDateString("en-CA", { timeZone: "America/Toronto" });
const bmWeekIdOf = (day) => { const x = new Date(day + "T12:00:00Z"), n = x.getUTCDay(); x.setUTCDate(x.getUTCDate() + (n === 0 ? -6 : 1 - n)); return x.toISOString().slice(0, 10); };
// D1 COST GUARD: the badminton app polls /api/bm/q and every call re-read whole tables (~16k reads/day of bm_games alone = 91% of the free
// 5M rows_read/day). Reads now share a short per-isolate cache (concurrent callers share one query); any write clears it. NEVER bypass this
// for read-only hot paths; writes pass fresh=true so they always merge into the latest rows.
const _bmCache = new Map(); const BM_CACHE_MS = 30000;
const bmCacheClear = () => _bmCache.clear();
const bmLoadRows = async (env, key, fresh) => {
  const hit = _bmCache.get(key);
  if (!fresh && hit && Date.now() - hit.at < BM_CACHE_MS) return hit.p.then((o) => o.map((x) => ({ ...x, row: { ...x.row } })));
  const p = (async () => {
    const res = (await env.DB.prepare(key === "players" ? "SELECT id, uid, data FROM bm_players" : `SELECT id, data FROM ${BM_TBL[key]}`).all()).results || [];
    const out = []; for (const r of res) { try { out.push({ id: r.id, uid: r.uid || null, row: JSON.parse(r.data) }); } catch {} }
    return out;
  })();
  _bmCache.set(key, { at: Date.now(), p }); p.catch(() => _bmCache.delete(key));
  return p.then((o) => o.map((x) => ({ ...x, row: { ...x.row } })));
};
const bmSaveStmt = (env, key, id, row, uid) => (bmCacheClear(), key === "players")
  ? env.DB.prepare("INSERT OR REPLACE INTO bm_players (id, uid, data) VALUES (?, ?, ?)").bind(id, uid ?? null, JSON.stringify(row))
  : env.DB.prepare(`INSERT OR REPLACE INTO ${BM_TBL[key]} (id, day, data) VALUES (?, ?, ?)`).bind(id, bmDay(row), JSON.stringify(row));
// The badminton player row for a 4DS member: the imported one (matched by phone) or a fresh one created on first use.
const bmPlayerFor = async (env, user) => {
  const row = await env.DB.prepare("SELECT id, data FROM bm_players WHERE uid = ?").bind(user.id).first();
  if (row) return { id: row.id, data: JSON.parse(row.data) };
  const digits = bmDigits(user.phone);
  const data = { id: `u:${user.id}`, name: firstNameOnly(user.name), full_name: user.name, username: digits, phone: digits, level: null, active: true, date_joined: bmToronto() };
  await env.DB.prepare("INSERT OR IGNORE INTO bm_players (id, uid, data) VALUES (?, ?, ?)").bind(data.id, user.id, JSON.stringify(data)).run();
  return { id: data.id, data };
};
// The iPad kiosk is protected by one fixed password (4ds1234, any capitalisation, no token / key to generate).
const bmKioskOk = async (env, key) => String(key || "").toUpperCase().replace(/[^A-Z0-9]/g, "") === "4DS1234";
const BM_HEARTS = ["❤️", "🧡", "💛", "💚", "💙", "💜", "🩷", "🤎"];
const bmDigits = (p) => { const d = String(p || "").replace(/\D/g, ""); return d.length === 11 && d[0] === "1" ? d.slice(1) : d; };
const bmDay = (r) => String((r && (r.session_date || r.played_at || r.day || r.date || r.created_at)) || "").slice(0, 10);
const bmRowId = async (table, r, i) => String((r && r.id) || (await sha256Hex(table + JSON.stringify(r) + i)).slice(0, 24));
// ---- Squads (separate from clubs): same member accounts, their own membership lists, requests and PRIVATE invite links ----
const SQUAD_TITLES = { quran: "Quran", badminton: "Badminton", cowork: "Cowork", steps: "Steps" };
// Squads no longer exist: each became a club (data/clubs.json). The old squad member lists are kept ONLY so existing members can confirm they want to stay (the /stay page).
const SQUAD_TO_CLUB = { quran: "club-quran", badminton: "club-badminton", cowork: "club-cowork", steps: "club-steps" };
const legacySquadClubsOf = async (env, uid) => { const out = []; for (const sid of Object.keys(SQUAD_TITLES)) if ((await readSquadMemberIds(env, sid)).includes(uid)) out.push(SQUAD_TO_CLUB[sid]); return out; };
const squadMembersKey = (id) => `squadmembers:${id}`;
const squadReqKey = (id, uid) => `squadreq:${id}:${uid}`;
const squadLinkKey = (id) => `squadlink:${id}`;
const readSquadMemberIds = async (env, id) => { try { return JSON.parse((await env.SITE_DATA.get(squadMembersKey(id))) || "[]"); } catch { return []; } };
const writeSquadMemberIds = (env, id, ids) => env.SITE_DATA.put(squadMembersKey(id), JSON.stringify(ids));
const notifyAdminOfJoinRequest = (env, ctx, user, club) => {
  if (!env.RESEND_API_KEY || !env.ADMIN_NOTIFY_EMAIL) return;
  const origin = env.SITE_ORIGIN || "https://4dasistas.ca";
  const f = user.form || {};
  const picks = Array.isArray(f.ranked) && f.ranked.length ? `<p style="margin:0 0 6px"><strong>Their picks:</strong> ${f.ranked.slice(0, 4).map((c, i) => `${i + 1}. ${escapeHtml(c)}`).join(" &nbsp; ")}</p>` : "";
  const html = emailShell(env, { emoji: "🙋‍♀️", title: "New club join request", preheader: `${user.name} → ${club.title}`,
    body: `<p style="margin:0 0 6px"><strong>${escapeHtml(user.name)}</strong> <span style="color:#776867">@${escapeHtml(user.username)}</span> asked to join</p><p style="margin:0 0 14px">${emailChip(escapeHtml(club.title))}</p>${user.phone ? `<p style="margin:0 0 6px">📞 ${escapeHtml(user.phone)}</p>` : ""}${picks}${f.why ? emailNote(`<div style="font-size:12px;opacity:.8;margin-bottom:2px">💬 What they wrote</div>${escapeHtml(String(f.why).slice(0, 400)).replace(/\n/g, "<br>")}`) : ""}<p style="margin:16px 0 4px">${emailBtn(origin + "/#/admin", "Review the request →")}</p>`,
    footer: "Accept or decline under 🏛️ Clubs → Notifications on your admin page." });
  sendAdminEmail(env, ctx, `Join request: ${user.name} → ${club.title}`, html);
};

// ---- Global username uniqueness index (username -> userId) ----
const usernameKey = (username) => `username:${username}`;

const findUserIdByUsername = async (env, username) => env.SITE_DATA.get(usernameKey(username));

const reserveUsername = async (env, username, userId) => {
  await env.SITE_DATA.put(usernameKey(username), userId);
};

const releaseUsername = async (env, username) => {
  await env.SITE_DATA.delete(usernameKey(username));
};

// ---- Member sessions (device sign-in tokens, scoped to a user, not a club) ----
const createMemberSession = async (env, userId) => {
  const token = crypto.randomUUID();
  await env.SITE_DATA.put(
    `membersession:${token}`,
    JSON.stringify({ userId, expiresAt: Date.now() + MEMBER_SESSION_TTL * 1000 }),
    { expirationTtl: MEMBER_SESSION_TTL }
  );
  return token;
};

const verifyMemberToken = async (env, userId, token) => {
  if (!token) return false;
  const raw = await env.SITE_DATA.get(`membersession:${token}`);
  if (!raw) return false;
  try {
    return JSON.parse(raw).userId === userId;
  } catch {
    return false;
  }
};

// ---- Club events (admin-created, members mark availability per event) ----
const clubEventsKey = (clubId) => `clubevents:${clubId}`;
const clubEventResponsesKey = (clubId, eventId) => `clubeventresponses:${clubId}:${eventId}`;

// ---- Event-idea boards: one shared document per club. Anyone can join with just a name (no password);
// a signed-in member uses their account name. Each option = title + Google Maps link (+ an admin-set date). ----
const clubIdeasKey = (clubId) => `clubideas:${clubId}`;
const IDEAS_MAX_PER_CLUB = 40;
const IDEAS_MAX_PER_PERSON = 3;
// The Cuisine club's boards are restaurant picks: every option needs a cuisine type, the place's name (the title)
// and a Google Maps link.
const CUISINE_CLUB_ID = "club-cuisine";
const sanitizeCuisine = (input) => String(input || "").replace(/[\x00-\x1f\x7f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, 30);
// An emoji the person picked for their bubble (anything non-plain-text, up to 8 characters); empty = the automatic one is used.
const sanitizeIdeaEmoji = (input) => { const t = String(input || "").replace(/[\x00-\x1f\x7f<>]/g, "").trim(); return t && t.length <= 8 && /[^\x00-\x7f]/.test(t) ? t : ""; };
const sanitizePrice = (input) => String(input || "").replace(/[\x00-\x1f\x7f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, 20);

// ---- "Add your availability" on each club's idea-board page: a light, 10-day version of the month-view
// calendar, open to anyone who can vote there (a signed-in member OR a name-only guest), not just full club
// members. One private document per person per club: { "YYYY-MM-DD": "busy" | ["morning","afternoon","evening"] }.
// "busy" = the whole day painted red by the Busy-all-day button; an array = only those segments are marked
// available (an array of all 3 = the same as the Available-all-day button, painted green).
const IDEA_AVAIL_PARTS = ["morning", "afternoon", "evening"];
// One availability record per person, shared across every club — not a separate one per
// club someone belongs to. Being free Tuesday evening doesn't depend on which club's page
// you're looking at it from.
const ideaAvailKey = (personId) => `ideaavail:${personId}`;
// Stored idea-availability docs are either the legacy bare days-map, or {name, days} (added so an admin
// overview can show WHO is free, not just a count — a guest's name only ever otherwise exists in their own
// browser's localStorage, never server-side, so it has to be captured at save time).
const parseIdeaAvailDoc = (raw) => {
  const empty = { name: "", days: {}, no: {}, submitted: false };
  if (!raw) return empty;
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return empty; }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return empty;
  const isDoc = parsed.days && typeof parsed.days === "object";
  const rawDays = isDoc ? parsed.days : parsed;
  const out = { name: isDoc ? String(parsed.name || "") : "", days: {}, no: {}, submitted: isDoc || Object.keys(rawDays).length > 0 };
  for (const [date, v] of Object.entries(rawDays)) {
    if (v === "busy") out.no[date] = allowedAvailParts(date); // legacy whole-day "busy" = every slot red
    else if (Array.isArray(v)) out.days[date] = v;
  }
  if (isDoc && parsed.no && typeof parsed.no === "object") for (const [date, v] of Object.entries(parsed.no)) if (Array.isArray(v)) out.no[date] = v;
  return out;
};
let _ideaAvailMemo = { at: 0, people: null };
const readIdeaAvailPeople = async (env) => {
  if (_ideaAvailMemo.people && Date.now() - _ideaAvailMemo.at < 45000) return _ideaAvailMemo.people.map((p) => ({ ...p })); // fewer KV reads: 45s per server instance
  let people;
  try {
    people = await readIdeaAvailPeopleFresh(env);
    saveSnapshot(env, "snap:iaPeople", people);
  } catch (e) {
    const snap = await readSnapshot(env, "snap:iaPeople"); // a quota/limit problem: show the last good copy instead of nothing
    if (!snap || !Array.isArray(snap.data)) throw e;
    people = snap.data;
  }
  _ideaAvailMemo = { at: Date.now(), people };
  return people.map((p) => ({ ...p }));
};
const readIdeaAvailPeopleFresh = async (env) => {
  if (await d1On(env)) {
    const rows = ((await env.DB.prepare("SELECT person_id, data FROM ideaavail").all()).results || []);
    const names = new Map(((await env.DB.prepare("SELECT id, name FROM users").all()).results || []).map((r) => [r.id, r.name]));
    const people = [];
    for (const r of rows) {
      if (!/^(m:|g:|admin$)/.test(r.person_id)) continue;
      const { name, days, no, submitted } = parseIdeaAvailDoc(r.data);
      if (!submitted) continue;
      let resolvedName = name;
      if (r.person_id.startsWith("m:")) { const n = names.get(r.person_id.slice(2)); if (n === undefined) continue; resolvedName = sanitizePersonName(n) || resolvedName; }
      people.push({ id: r.person_id, name: resolvedName || "Someone", days, no });
    }
    return people;
  }
  let ids = await readIndex(env, IA_INDEX_KEY);
  if (!ids) { // built from a list once, then maintained on every save
    try {
      ids = (await env.SITE_DATA.list({ prefix: `ideaavail:` })).keys.map((k) => k.name.slice(`ideaavail:`.length)).filter((id) => /^(m:|g:|admin$)/.test(id));
      await env.SITE_DATA.put(IA_INDEX_KEY, JSON.stringify(ids)).catch(() => {});
    } catch (e) { ids = (await idsFromClubMembers(env)).map((id) => `m:${id}`).concat(["admin"]); } // list not possible right now: everyone in a club, via plain GETs
  }
  const people = [];
  for (const personId of ids) {
    const k = { name: `ideaavail:${personId}` };
    // Skip LEGACY per-club records (`ideaavail:club-xxx:<person>`, from before availability became one global record):
    // nothing writes them any more, but they were still being listed — that's why someone in 4 clubs showed up 4 times.
    if (!/^(m:|g:|admin$)/.test(personId)) continue;
    const { name, days, no, submitted } = parseIdeaAvailDoc(await env.SITE_DATA.get(k.name));
    // Anyone who submitted counts as a respondent - even with an empty grid (= available everywhere, no preferred times).
    if (!submitted) continue;
    let resolvedName = name;
    if (personId.startsWith("m:")) {
      // a record whose profile was deleted (or never existed) must not keep showing up; and use the profile's CURRENT name
      const user = await readUser(env, personId.slice(2));
      if (!user) continue;
      resolvedName = sanitizePersonName(user.name) || resolvedName;
    }
    people.push({ id: personId, name: resolvedName || "Someone", days, no });
  }
  return people;
};
// Weekday mornings aren't offered (work/school) - mornings exist for Sat/Sun only.
const isWeekendDate = (date) => { const d = new Date(date + "T12:00:00Z").getUTCDay(); return d === 0 || d === 6; };
const allowedAvailParts = (date) => (isWeekendDate(date) ? IDEA_AVAIL_PARTS : IDEA_AVAIL_PARTS.filter((p) => p !== "morning"));
// Per slot a person is GREEN (preferred = in `days`), RED (can't = in `no`) or unset (counts as available, just not
// preferred). Returns {days, no}; a slot can never be both.
const sanitizeIdeaAvailDays = (input) => {
  const out = {};
  if (!input || typeof input !== "object" || Array.isArray(input)) return out;
  const today = new Date();
  const minDate = new Date(today.getTime() - 3 * 86400000).toISOString().slice(0, 10);
  const maxDate = new Date(today.getTime() + 45 * 86400000).toISOString().slice(0, 10);
  for (const [date, val] of Object.entries(input)) {
    if (Object.keys(out).length >= 60) break;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || date < minDate || date > maxDate) continue;
    if (Number.isNaN(Date.parse(date + "T00:00:00Z"))) continue;
    if (Array.isArray(val)) {
      const clean = allowedAvailParts(date).filter((p) => val.includes(p));
      if (clean.length) out[date] = clean;
    }
  }
  return out;
};
const sanitizeIdeaAvail = (body) => {
  const raw = body && typeof body === "object" ? body : {};
  const noInput = {};
  const daysInput = {};
  if (raw.days && typeof raw.days === "object" && !Array.isArray(raw.days)) {
    for (const [d, v] of Object.entries(raw.days)) { if (v === "busy") noInput[d] = IDEA_AVAIL_PARTS; else daysInput[d] = v; }
  }
  if (raw.no && typeof raw.no === "object" && !Array.isArray(raw.no)) for (const [d, v] of Object.entries(raw.no)) noInput[d] = v;
  const days = sanitizeIdeaAvailDays(daysInput);
  const no = sanitizeIdeaAvailDays(noInput);
  for (const [d, parts] of Object.entries(no)) {
    const rest = parts.filter((p) => !(days[d] || []).includes(p));
    if (rest.length) no[d] = rest; else delete no[d];
  }
  return { days, no };
};
const readClubIdeas = async (env, clubId) => {
  const raw = await env.SITE_DATA.get(clubIdeasKey(clubId));
  try { const d = raw ? JSON.parse(raw) : {}; return Array.isArray(d.ideas) ? d.ideas : []; } catch { return []; }
};
const writeClubIdeas = async (env, clubId, ideas) => env.SITE_DATA.put(clubIdeasKey(clubId), JSON.stringify({ ideas }));
const sanitizePersonName = (input) => String(input || "").replace(/[\x00-\x1f\x7f<>]/g, "").replace(/\s+/g, " ").trim().slice(0, 30);
// Accepts what people actually paste from Google Maps: the bare link, a link with text around it
// ("Sultan's Table https://maps.app.goo.gl/…"), or a link with no https:// in front. Always returns an https URL.
const isGoogleMapsUrl = (input) => {
  try {
    let raw = String(input || "").trim();
    const found = raw.match(/https?:\/\/[^\s<>"']+/i) || raw.match(/(?:www\.google\.[a-z.]{2,6}\/maps|google\.[a-z.]{2,6}\/maps|maps\.app\.goo\.gl|maps\.google\.[a-z.]{2,6}|goo\.gl\/maps|g\.page|share\.google|g\.co\/kgs)[^\s<>"\']*/i);
    if (found) raw = /^https?:\/\//i.test(found[0]) ? found[0] : "https://" + found[0];
    const u = new URL(raw.replace(/^http:\/\//i, "https://"));
    if (u.protocol !== "https:") return null;
    const h = u.hostname.toLowerCase();
    const ok = h === "maps.app.goo.gl" || h === "share.google" || h === "g.page" || h === "goo.gl" && u.pathname.startsWith("/maps") ||
      (h === "g.co" && u.pathname.startsWith("/kgs")) ||
      (/^maps\.google\.[a-z.]{2,6}$/.test(h)) ||
      ((h === "google.com" || h.endsWith(".google.com") || /^(www\.)?google\.[a-z]{2,3}(\.[a-z]{2})?$/.test(h)) && u.pathname.startsWith("/maps"));
    return ok && u.href.length <= 500 ? u.href : null;
  } catch { return null; }
};
const ideaPeople = (idea) => ({
  by: idea.by && typeof idea.by === "object" ? idea.by : { id: String(idea.by || ""), name: "Member" },
  voters: (Array.isArray(idea.votes) ? idea.votes : []).map((v) => (typeof v === "object" ? v : { id: String(v), name: "Member" })),
});
// Automatic emoji for an idea, picked from its title / cuisine (so every submitted activity gets one). Falls back to the
// club's own emoji, then a sparkle. Admins can override it when editing.
const IDEA_EMOJI_RULES = [
  [/thai|pad ?thai|curry|laksa|tom yum/i, "🍜"], [/ramen|noodle|pho\b|udon|soba|dumpling|dim ?sum/i, "🍜"], [/sushi|japan|omakase|hibachi|teppanyaki/i, "🍣"],
  [/korean|k-?bbq|bulgogi|kimchi|galbi/i, "🥩"], [/pizza|pizzeria/i, "🍕"], [/burger|smash/i, "🍔"], [/taco|mexican|burrito|nacho|quesadilla/i, "🌮"],
  [/shawarma|wrap|kebab|falafel|lebanese|syrian|turkish|mandi|mezze|mezza|grill|gyro/i, "🥙"], [/biryani|indian|pakistani|desi|karahi|nihari|tikka|butter chicken|halal cart/i, "🍛"],
  [/pasta|italian|spaghetti|lasagn|risotto/i, "🍝"], [/dessert|ice ?cream|gelato|waffle|crepe|cake|bakery|donut|cookie|sweet|baklava|kunafa|knafeh|pastry|cheesecake/i, "🍰"],
  [/coffee|cafe|café|latte|matcha|\btea\b|boba|bubble tea|chai/i, "☕"], [/brunch|breakfast|pancake|french toast/i, "🥞"], [/seafood|fish|lobster|crab|shrimp|oyster/i, "🦐"],
  [/chicken|wings|fried|nando/i, "🍗"], [/poutine|fries/i, "🍟"], [/picnic/i, "🧺"], [/steak|prime|ribs/i, "🥩"], [/salad|vegan|vegetarian|healthy|bowl/i, "🥗"],
  [/dinner|restaurant|lunch|eat\b|food|feast|potluck|buffet|crawl/i, "🍽️"],
  [/pottery|ceramic|clay|wheel/i, "🏺"], [/paint|canvas|sketch|draw|craft|diy|workshop|crochet|knit|embroider|calligraph|art\b/i, "🎨"], [/candle|soap|resin|jewel|bead/i, "🕯️"],
  [/photo|photograph|photoshoot/i, "📸"], [/escape room|escape/i, "🔐"], [/laser tag|paintball|axe|archery|shooting/i, "🎯"], [/vr\b|virtual reality|arcade|gaming|game night|board game|trampoline|karting|go.?kart|bowling|billiard|pool hall/i, "🎮"],
  [/hike|hiking|trail|trek|waterfall|conservation/i, "🥾"], [/lake|beach|swim|kayak|canoe|paddle|boat|cruise|island/i, "🌊"], [/camp|cabin|bonfire|glamp|retreat|cottage/i, "🏕️"],
  [/ski|snow|skat|ice rink|sledd?/i, "⛷️"], [/bike|cycl|ride\b/i, "🚴"], [/yoga|pilates|stretch|meditat|wellness|spa\b|massage/i, "🧘"],
  [/badminton|pickleball|tennis|court|padel|volleyball|basketball|soccer|football|sport|run club|\brun\b/i, "🏸"], [/walk|steps|stroll/i, "🚶"],
  [/book|read|library|novel|story/i, "📚"], [/movie|film|cinema|theatre|theater|musical|show\b/i, "🎬"], [/concert|music|karaoke|sing|open mic/i, "🎤"], [/museum|gallery|exhibit|aquarium|zoo/i, "🖼️"],
  [/shop|market|mall|thrift|bazaar|boutique/i, "🛍️"], [/flower|garden|bloom|tulip|blossom|farm|apple|pumpkin|berry|orchard|maze/i, "🌸"],
  [/trip|travel|road ?trip|getaway|day trip|niagara|toronto|montreal|ottawa|banff/i, "🧳"], [/quran|dua\b|halaqa|islamic|mosque|masjid|iftar|ramadan|eid\b|taraweeh/i, "🕌"],
  [/party|birthday|celebrat|bridal|henna|mehndi|sleepover|gala/i, "🎉"], [/cowork|study|work session|laptop/i, "💻"], [/dance|zumba|salsa/i, "💃"], [/swim/i, "🏊"],
];
const pickIdeaEmoji = (title, cuisine, fallback) => {
  const text = `${title || ""} ${cuisine || ""}`;
  for (const [re, em] of IDEA_EMOJI_RULES) if (re.test(text)) return em;
  return fallback || "✨";
};
const publicIdea = (idea, me) => {
  const { by, voters } = ideaPeople(idea);
  return {
    id: idea.id, title: idea.title, mapUrl: idea.mapUrl || "", date: idea.date || "", cuisine: idea.cuisine || "", price: idea.price || "",
    emoji: idea.emoji || pickIdeaEmoji(idea.title, idea.cuisine, ""),
    votes: Math.max(0, voters.length + (idea.adjust || 0)), adjust: idea.adjust || 0,
    // Only signed-in members and the admin see who added / voted; the public (and name-only guests) get a flag instead.
    namesHidden: !(me && (me.id === "admin" || me.id.startsWith("m:"))),
    voters: me && (me.id === "admin" || me.id.startsWith("m:")) ? voters.map((v) => v.name) : [],
    by: me && (me.id === "admin" || me.id.startsWith("m:")) ? by.name : "",
    done: !!idea.done, doneDate: idea.doneDate || "",
    voted: !!me && voters.some((v) => v.id === me.id), mine: !!me && by.id === me.id,
  };
};
const sortedPublicIdeas = (ideas, me) => ideas.map((i) => publicIdea(i, me)).sort((a, b) => b.votes - a.votes || a.title.localeCompare(b.title));
// Best-effort per-IP throttle for idea writes (in-memory, so it costs no KV writes).
const ideaRate = new Map();
const ideaRateOk = (ip) => {
  const now = Date.now();
  if (ideaRate.size > 5000) ideaRate.clear();
  const e = ideaRate.get(ip);
  if (!e || now > e.reset) { ideaRate.set(ip, { n: 1, reset: now + 60000 }); return true; }
  e.n += 1;
  return e.n <= 40;
};

// ---- Month-view availability: one private document per member per club ----
const AVAILABILITY_PARTS = ["morning", "afternoon", "night"];
const clubAvailabilityKey = (clubId, userId) => `clubavailability:${clubId}:${userId}`;
const sanitizeAvailabilityDays = (input) => {
  const out = {};
  if (!input || typeof input !== "object" || Array.isArray(input)) return out;
  const today = new Date();
  const minDate = new Date(today.getTime() - 60 * 86400000).toISOString().slice(0, 10);
  const maxDate = new Date(today.getTime() + 400 * 86400000).toISOString().slice(0, 10);
  for (const [date, parts] of Object.entries(input)) {
    if (Object.keys(out).length >= 500) break;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || date < minDate || date > maxDate) continue;
    if (Number.isNaN(Date.parse(date + "T00:00:00Z"))) continue;
    if (!Array.isArray(parts)) continue;
    const clean = AVAILABILITY_PARTS.filter((p) => parts.includes(p));
    if (clean.length) out[date] = clean;
  }
  return out;
};

const readClubEvents = async (env, clubId) => {
  const raw = await env.SITE_DATA.get(clubEventsKey(clubId));
  return raw ? JSON.parse(raw) : [];
};

const writeClubEvents = async (env, clubId, events) => {
  await env.SITE_DATA.put(clubEventsKey(clubId), JSON.stringify(events));
};

// ---- Club calendar: one KV doc holds every club's events ({id, clubId, title, date, time, place, desc, rsvps:[{id,name,status:"going"|"pending",at}]}). ----
// The public sees only title + date; details and RSVP need a member sign-in. Members of the club are "going" at once; anyone else becomes "pending" until an admin accepts.
let _calIdeaCache = null;
const CLUBCAL_KEY = "clubcal";
const readClubCal = async (env) => { try { const r = await env.SITE_DATA.get(CLUBCAL_KEY); const a = r ? JSON.parse(r) : []; return Array.isArray(a) ? a : []; } catch { return []; } };
const writeClubCal = (env, a) => env.SITE_DATA.put(CLUBCAL_KEY, JSON.stringify(a));
const cleanCalText = (v, n) => String(v || "").replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
// A collab event belongs to several clubs: `clubIds` (clubId = the first, kept for older data).
const calClubs = (e) => (Array.isArray(e.clubIds) && e.clubIds.length ? e.clubIds : [e.clubId]).filter(Boolean);
// A sign-up form the admin builds for an event: {title, intro, fields:[{id,type,label,required,options?}]}. Answers live in KV `calform:<eventId>` (userId -> {name, answers, at}).
const CAL_FIELD_TYPES = ["text", "longtext", "yesno", "choice", "multi", "number", "date", "location"];
const calFormKey = (eventId) => `calform:${eventId}`;
const sanitizeCalForm = (f) => {
  if (!f || typeof f !== "object" || !Array.isArray(f.fields)) return null;
  const fields = [], seen = new Set();
  for (const x of f.fields.slice(0, 30)) {
    if (!x || !CAL_FIELD_TYPES.includes(x.type)) continue;
    const label = String(x.label || "").replace(/[\x00-\x08\x0b-\x1f\x7f<>]/g, " ").replace(/[ \t]+/g, " ").trim().slice(0, 1000); if (!label) continue; // long questions (and line breaks) are allowed
    let id = /^[a-z0-9]{3,16}$/.test(String(x.id || "")) ? String(x.id) : crypto.randomUUID().slice(0, 8);
    if (seen.has(id)) id = crypto.randomUUID().slice(0, 8);
    seen.add(id);
    const fld = { id, type: x.type, label, required: !!x.required };
    if (x.type === "choice" || x.type === "multi") { fld.options = (Array.isArray(x.options) ? x.options : []).map((o) => cleanCalText(o, 160)).filter(Boolean).slice(0, 12); if (fld.options.length < 2) continue; }
    fields.push(fld);
  }
  if (!fields.length) return null;
  const longText = (v, n) => String(v || "").replace(/[\x00-\x08\x0b-\x1f\x7f<>]/g, " ").trim().slice(0, n);
  const out = { title: cleanCalText(f.title, 140) || "Sign-up form", intro: longText(f.intro, 2000), fields };
  if (typeof f.rsvpBy === "string") out.rsvpBy = /^\d{4}-\d{2}-\d{2}$/.test(f.rsvpBy) ? f.rsvpBy : ""; // the form builder can set the event's last RSVP day (moved onto the event below)
  if (typeof f.desc === "string") out.desc = longText(f.desc, 3000); // the EVENT description (set from the form builder; lives on the event, not in the form)
  const footer = longText(f.footer, 3000); if (footer) out.footer = footer; // description shown at the bottom of the form
  // Payment: the site doesn't take money itself — it shows how to pay (an amount, a payment link, instructions) once someone has signed up.
  if (f.payment && typeof f.payment === "object") {
    let link = ""; try { const u = new URL(String(f.payment.link || "").trim()); if (u.protocol === "https:") link = u.href.slice(0, 500); } catch {}
    const pay = { amount: cleanCalText(f.payment.amount, 30), link, note: longText(f.payment.note, 1000) };
    // Add-ons: optional extras people can tick (e.g. "T-shirt +$10"); the total = the amount above + the ticked add-ons.
    const seenA = new Set(), addons = [];
    for (const a of (Array.isArray(f.payment.addons) ? f.payment.addons : []).slice(0, 12)) {
      const label = cleanCalText(a && a.label, 60), price = Math.round(Number(a && a.price) * 100) / 100;
      if (!label || !Number.isFinite(price) || price < 0 || price > 10000) continue;
      let id = /^[a-z0-9]{3,16}$/.test(String((a && a.id) || "")) ? String(a.id) : crypto.randomUUID().slice(0, 8);
      if (seenA.has(id)) id = crypto.randomUUID().slice(0, 8);
      seenA.add(id); addons.push({ id, label, price });
    }
    if (addons.length) pay.addons = addons;
    if (pay.amount || pay.link || pay.note || pay.addons) out.payment = pay;
  }
  return out;
};
// ---- Event page design: text uses a tiny markup the browser renders safely (**bold**, *italic*, links…); the page is also a list of BLOCKS (text, photo, map, button, video, divider) plus a theme ----
const calPlain = (s) => String(s || "").replace(/\{[a-z ]+\}|\{\/\}/g, "").replace(/\[([^\]]+)\]\([^)\s]+\)/g, "$1").replace(/\*\*|__|~~|==/g, "").replace(/(^|[^*\w])\*([^*\n]+)\*/g, "$1$2");
const CAL_IMG_RE = /^[a-z0-9]{8,24}$/;
const calHttps = (v, n = 500) => { try { const u = new URL(String(v || "").trim()); return u.protocol === "https:" && u.href.length <= n ? u.href : ""; } catch { return ""; } };
const calLinkOk = (v) => { const t = String(v || "").trim(); if (/^(mailto:|tel:)[^\s<>"']{3,120}$/i.test(t)) return t; return calHttps(t); };
const calEmbedSrc = (v) => { // a Google Maps "Embed a map" iframe (or just its src) -> the safe src, else ""
  const m = String(v || "").match(/src\s*=\s*["']([^"']+)["']/i), raw = (m ? m[1] : String(v || "")).trim().replace(/&amp;/g, "&");
  try { const u = new URL(raw); return u.protocol === "https:" && u.hostname === "www.google.com" && u.pathname.startsWith("/maps/embed") && u.href.length <= 1500 ? u.href : ""; } catch { return ""; }
};
const calYoutubeId = (v) => { const m = String(v || "").match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?(?:.*&)?v=|embed\/|shorts\/|live\/))([\w-]{11})/i); return m ? m[1] : ""; };
const sanitizeCalBlocks = (arr) => {
  const out = [], seen = new Set(), txt = (v, n) => String(v || "").replace(/[\x00-\x08\x0b-\x1f\x7f<>]/g, " ").trim().slice(0, n);
  const pick = (v, list, d) => (list.includes(v) ? v : d);
  for (const b of (Array.isArray(arr) ? arr : []).slice(0, 40)) {
    if (!b || typeof b !== "object") continue;
    let id = /^[a-z0-9]{3,16}$/.test(String(b.id || "")) ? String(b.id) : crypto.randomUUID().slice(0, 8);
    if (seen.has(id)) id = crypto.randomUUID().slice(0, 8);
    let o = null;
    if (b.type === "text") { const t = txt(b.text, 4000); if (t) o = { type: "text", text: t, align: pick(b.align, ["left", "center", "right"], "left") }; }
    else if (b.type === "image") {
      const img = CAL_IMG_RE.test(String(b.img || "")) ? String(b.img) : "", url = img ? "" : calHttps(b.url);
      if (img || url) { o = { type: "image", ...(img ? { img } : { url }), caption: txt(b.caption, 300), size: pick(b.size, ["small", "medium", "large", "full"], "full"), align: pick(b.align, ["left", "center", "right"], "center") }; const lk = calLinkOk(b.link); if (lk) o.link = lk; }
    }
    else if (b.type === "map") {
      const embed = calEmbedSrc(b.embed), link = b.link ? (isGoogleMapsUrl(b.link) || "") : "", q = txt(b.q, 200);
      if (embed || link || q) o = { type: "map", ...(embed ? { embed } : {}), ...(link ? { link } : {}), ...(q ? { q } : {}), height: pick(b.height, ["small", "medium", "large"], "medium"), caption: txt(b.caption, 300) };
    }
    else if (b.type === "button") { const label = txt(b.label, 60), url = calLinkOk(b.url); if (label && url) o = { type: "button", label, url, style: pick(b.style, ["solid", "outline"], "solid"), align: pick(b.align, ["left", "center", "right"], "center") }; }
    else if (b.type === "video") { const vid = calYoutubeId(b.url || b.vid); if (vid) o = { type: "video", vid, caption: txt(b.caption, 300) }; }
    else if (b.type === "divider") o = { type: "divider" };
    if (o) { seen.add(id); out.push({ id, ...o }); }
  }
  return out;
};
// Hosts shown as round logos at the top of the page: a club of the event (can override its name / logo / link, or be hidden) or an outside organisation. A logo is an uploaded photo (`logo`) or another club's logo (`logoClub`).
const sanitizeCalHosts = (arr) => {
  const out = [], seen = new Set(), txt = (v, n) => String(v || "").replace(/[\x00-\x1f\x7f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
  for (const h of (Array.isArray(arr) ? arr : []).slice(0, 12)) {
    if (!h || typeof h !== "object") continue;
    const club = /^[\w-]{1,60}$/.test(String(h.club || "")) ? String(h.club) : "", name = txt(h.name, 60);
    if (!club && !name) continue;
    let id = /^[a-z0-9]{3,16}$/.test(String(h.id || "")) ? String(h.id) : crypto.randomUUID().slice(0, 8);
    if (seen.has(id)) id = crypto.randomUUID().slice(0, 8);
    seen.add(id);
    const logo = CAL_IMG_RE.test(String(h.logo || "")) ? String(h.logo) : "", logoClub = !logo && /^[\w-]{1,60}$/.test(String(h.logoClub || "")) ? String(h.logoClub) : "", link = calLinkOk(h.link);
    out.push({ id, ...(club ? { club } : {}), ...(name ? { name } : {}), ...(logo ? { logo } : {}), ...(logoClub ? { logoClub } : {}), ...(link ? { link } : {}), ...(club && h.hide ? { hide: true } : {}) });
  }
  return out;
};
const sanitizeCalTheme = (t) => {
  if (!t || typeof t !== "object") return null;
  const o = {}, hex = (v) => (/^#[0-9a-f]{6}$/i.test(String(v || "")) ? String(v).toLowerCase() : "");
  if (hex(t.accent)) o.accent = hex(t.accent);
  if (hex(t.bg)) o.bg = hex(t.bg);
  if (CAL_IMG_RE.test(String(t.cover || ""))) o.cover = String(t.cover);
  if (["serif", "rounded", "mono"].includes(t.font)) o.font = t.font;
  if (t.titleAlign === "center") o.titleAlign = "center";
  return Object.keys(o).length ? o : null;
};
// Which design bits a request body sets (undefined = leave as is).
const calDesignFields = (b) => { const o = {}; if (b.blocks !== undefined) o.blocks = sanitizeCalBlocks(b.blocks); if (b.theme !== undefined) o.theme = sanitizeCalTheme(b.theme); if (b.hosts !== undefined) o.hosts = sanitizeCalHosts(b.hosts); return o; };
const calDesignFieldsObj = (b) => { const d = calDesignFields(b), o = {}; if (d.blocks && d.blocks.length) o.blocks = d.blocks; if (d.theme) o.theme = d.theme; if (d.hosts && d.hosts.length) o.hosts = d.hosts; return o; };
const calApplyDesign = (ev, d) => { if (d.blocks !== undefined) { if (d.blocks.length) ev.blocks = d.blocks; else delete ev.blocks; } if (d.theme !== undefined) { if (d.theme) ev.theme = d.theme; else delete ev.theme; } if (d.hosts !== undefined) { if (d.hosts.length) ev.hosts = d.hosts; else delete ev.hosts; } };
let _calImgReady = false;
const calImgEnsure = async (env) => { if (_calImgReady) return; await env.DB.prepare("CREATE TABLE IF NOT EXISTS cal_images (id TEXT PRIMARY KEY, ev TEXT, ctype TEXT, b64 TEXT NOT NULL, at INTEGER)").run(); _calImgReady = true; };
const calImgSave = async (request, env, evId) => {
  const ctype = (request.headers.get("Content-Type") || "").split(";")[0].trim();
  if (!["image/jpeg", "image/png", "image/webp", "image/gif"].includes(ctype)) return { error: "Photos only (JPG, PNG, WebP or GIF)" };
  const buf = new Uint8Array(await request.arrayBuffer());
  if (!buf.length) return { error: "Empty photo" };
  if (buf.length > 900000) return { error: "That photo is too big — try a smaller one" };
  await calImgEnsure(env);
  if (evId) { const n = (await env.DB.prepare("SELECT COUNT(*) AS n FROM cal_images WHERE ev = ?").bind(evId).first()).n; if (n >= 40) return { error: "This event already has 40 photos" }; }
  let bin = ""; for (let i = 0; i < buf.length; i += 8192) bin += String.fromCharCode(...buf.subarray(i, i + 8192));
  const id = Array.from(crypto.getRandomValues(new Uint8Array(9)), (x) => (x % 36).toString(36)).join("");
  await env.DB.prepare("INSERT INTO cal_images (id, ev, ctype, b64, at) VALUES (?, ?, ?, ?, ?)").bind(id, evId || "", ctype, btoa(bin), Date.now()).run();
  return { id, url: `/api/cal-img/${id}` };
};
const calEditSnap = (ev) => ({ at: Date.now(), title: ev.title, date: ev.date, time: ev.time || "", place: ev.place || "", mapUrl: ev.mapUrl || "", desc: ev.desc || "", rsvpBy: ev.rsvpBy || "", blocks: ev.blocks || null, theme: ev.theme || null, hosts: ev.hosts || null, form: ev.form || null });
// Check one person's answers against the form; returns {answers} or {error}.
// Which add-ons were ticked + the total owed (only when the base amount is a number like "$15").
const calAddonSelection = (form, ids) => {
  const pay = (form && form.payment) || {}, list = Array.isArray(pay.addons) ? pay.addons : [];
  const picked = list.filter((a) => (Array.isArray(ids) ? ids : []).map(String).includes(a.id));
  const base = parseFloat(String(pay.amount || "").replace(/[^0-9.]/g, ""));
  const sum = picked.reduce((t, a) => t + a.price, 0);
  return { ids: picked.map((a) => a.id), total: Number.isFinite(base) ? Math.round((base + sum) * 100) / 100 : (picked.length ? Math.round(sum * 100) / 100 : null) };
};
const checkCalAnswers = (form, raw) => {
  const answers = {};
  for (const fld of form.fields) {
    let v = raw && raw[fld.id];
    if (fld.type === "multi") v = (Array.isArray(v) ? v : []).map(String).filter((o) => fld.options.includes(o));
    else if (fld.type === "choice") v = fld.options.includes(String(v)) ? String(v) : "";
    else if (fld.type === "yesno") v = v === "Yes" || v === "No" ? v : "";
    else if (fld.type === "number") v = v === "" || v == null ? "" : (Number.isFinite(Number(v)) ? String(Number(v)).slice(0, 20) : "");
    else if (fld.type === "date") v = /^\d{4}-\d{2}-\d{2}$/.test(String(v || "")) ? String(v) : "";
    else if (fld.type === "location") { // a place picked on the map (Canada only): {address, lat, lng}; the pin is dropped if the coordinates aren't in Canada
      const o = v && typeof v === "object" ? v : null, lat = Number(o && o.lat), lng = Number(o && o.lng), address = cleanCalText(o && o.address, 200);
      v = address ? { address, ...(Number.isFinite(lat) && Number.isFinite(lng) && lat >= 41 && lat <= 84 && lng >= -142 && lng <= -52 ? { lat: Math.round(lat * 1e5) / 1e5, lng: Math.round(lng * 1e5) / 1e5 } : {}) } : "";
    }
    else v = String(v || "").replace(/[\x00-\x08\x0b-\x1f\x7f]/g, " ").trim().slice(0, fld.type === "longtext" ? 1000 : 200);
    const empty = Array.isArray(v) ? !v.length : v === "";
    if (fld.required && empty) return { error: `Please answer: ${calPlain(fld.label)}` };
    if (!empty) answers[fld.id] = v;
  }
  return { answers };
};
// ---- BIG EVENTS: capacity + waitlist, safe concurrent sign-ups, reminders ----
// Spots are claimed with ONE atomic D1 statement (table cal_spots) so two people can never take the last spot; everyone past the limit is "waitlist" (first come, first served).
// The event list itself is a single KV doc, so every sign-up re-reads it fresh and re-checks after writing (calMutate) — and KV allows ~1 write/second per key, so a rush retries with a short back-off.
let _spotsReady = null;
const spotsEnsure = async (env) => {
  if (!env.DB) return false;
  if (!_spotsReady) _spotsReady = env.DB.prepare("CREATE TABLE IF NOT EXISTS cal_spots (event_id TEXT NOT NULL, pid TEXT NOT NULL, at INTEGER, PRIMARY KEY (event_id, pid))").run().catch((e) => { _spotsReady = null; throw e; });
  await _spotsReady; return true;
};
const calCap = (ev) => Math.max(0, Number(ev && ev.capacity) || 0);
const calGoingN = (ev) => (ev.rsvps || []).filter((r) => r.status === "going").length;
const calWaitPos = (ev, pid) => { const w = (ev.rsvps || []).filter((r) => r.status === "waitlist").sort((a, b) => (a.at || 0) - (b.at || 0)); const i = w.findIndex((r) => r.id === pid); return i < 0 ? 0 : i + 1; };
const calCapInfo = (ev) => { const cap = calCap(ev); return cap ? { capacity: cap, spotsLeft: Math.max(0, cap - calGoingN(ev)), waitCount: (ev.rsvps || []).filter((r) => r.status === "waitlist").length } : { capacity: 0 }; };
// Take a spot (atomic). force = an admin adding/accepting someone: always allowed, even over the limit.
const calClaimSpot = async (env, ev, pid, force) => {
  const cap = calCap(ev); if (!cap || !(await spotsEnsure(env))) return true;
  if (force) { await env.DB.prepare("INSERT OR IGNORE INTO cal_spots (event_id, pid, at) VALUES (?, ?, ?)").bind(ev.id, pid, Date.now()).run(); return true; }
  await env.DB.prepare("INSERT OR IGNORE INTO cal_spots (event_id, pid, at) SELECT ?, ?, ? WHERE (SELECT COUNT(*) FROM cal_spots WHERE event_id = ?) < ?").bind(ev.id, pid, Date.now(), ev.id, cap).run();
  return !!(await env.DB.prepare("SELECT 1 AS x FROM cal_spots WHERE event_id = ? AND pid = ?").bind(ev.id, pid).first());
};
const calSpotStatus = async (env, ev, pid) => ((await calClaimSpot(env, ev, pid, false)) ? "going" : "waitlist");
const calReleaseSpot = async (env, evId, pid) => { try { if (await spotsEnsure(env)) await env.DB.prepare("DELETE FROM cal_spots WHERE event_id = ? AND pid = ?").bind(evId, pid).run(); } catch {} };
// Rebuild the claims from the event's current "going" list (used when the limit is first set or changed).
const calSyncSpots = async (env, ev) => {
  if (!(await spotsEnsure(env))) return;
  const stmts = [env.DB.prepare("DELETE FROM cal_spots WHERE event_id = ?").bind(ev.id)];
  if (calCap(ev)) for (const r of (ev.rsvps || []).filter((x) => x.status === "going")) stmts.push(env.DB.prepare("INSERT OR IGNORE INTO cal_spots (event_id, pid, at) VALUES (?, ?, ?)").bind(ev.id, r.id, r.at || Date.now()));
  await env.DB.batch(stmts);
};
const sleepMs = (n) => new Promise((r) => setTimeout(r, n));
// ---- Readable event links: 4dasistas.ca/#/form/big-dinner instead of a random id. Slug = the title; a clash adds the date. Old random-id links and old slugs keep working. ----
const CAL_SLUG_RESERVED = new Set(["tbd", "form", "new", "paid", "rsvp", "attendees", "interest", "message"]);
const calSlugify = (t) => String(t || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/&/g, " and ").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 50).replace(/-+$/g, "");
const calMakeSlug = (all, ev) => {
  const taken = (x) => CAL_SLUG_RESERVED.has(x) || all.some((e) => e !== ev && e.id !== ev.id && (e.slug === x || (e.oldSlugs || []).includes(x))) || /^[0-9a-f]{8}-[0-9a-f]{4}-/.test(x);
  const base = calSlugify(ev.title) || "event";
  for (const c of [base, ev.date ? `${base}-${ev.date}` : ""]) if (c && !taken(c)) return c;
  for (let i = 2; i < 100; i++) { const c = `${base}-${i}`; if (!taken(c)) return c; }
  return `${base}-${crypto.randomUUID().slice(0, 4)}`;
};
const calEnsureSlugs = (all) => { let changed = false; for (const e of all) if (!e.slug) { e.slug = calMakeSlug(all, e); changed = true; } return changed; };
const calFind = (all, key) => all.find((e) => e.id === key || e.slug === key) || all.find((e) => (e.oldSlugs || []).includes(key));
const calBackfillSlugs = (env) => calWithLock(env, "cal:events", async () => { const all = await readClubCal(env); if (calEnsureSlugs(all)) await writeClubCal(env, all); }).catch(() => {});
// A tiny lock in D1 (one atomic statement) so two sign-ups never read-modify-write the same KV doc at once. Expires by itself after 8s.
let _lockReady = null;
const calWithLock = async (env, key, fn) => {
  let held = false;
  try {
    if (env.DB) {
      if (!_lockReady) _lockReady = env.DB.prepare("CREATE TABLE IF NOT EXISTS cal_locks (k TEXT PRIMARY KEY, exp INTEGER NOT NULL)").run().catch((e) => { _lockReady = null; throw e; });
      await _lockReady;
      for (let i = 0; i < 50 && !held; i++) {
        const r = await env.DB.prepare("INSERT INTO cal_locks (k, exp) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET exp = excluded.exp WHERE cal_locks.exp < ?").bind(key, Date.now() + 8000, Date.now()).run();
        if (r && r.meta && r.meta.changes > 0) held = true; else await sleepMs(100 + (i % 5) * 40);
      }
    }
  } catch (e) { console.log("calWithLock", String(e && e.message)); }
  try { return await fn(); }
  finally { if (held) await env.DB.prepare("DELETE FROM cal_locks WHERE k = ?").bind(key).run().catch(() => {}); }
};
// Fresh read → change → write → check it stuck (KV is one doc for all events, so two sign-ups at once could otherwise overwrite each other).
const calMutate = (env, evId, fn, verify) => calWithLock(env, "cal:events", () => calMutateRaw(env, evId, fn, verify));
const calMutateRaw = async (env, evId, fn, verify) => {
  for (let i = 0; i < 5; i++) {
    try {
      const all = await readClubCal(env), ev = all.find((e) => e.id === evId); if (!ev) return null;
      fn(ev); await writeClubCal(env, all);
      const chk = (await readClubCal(env)).find((e) => e.id === evId);
      if (chk && (!verify || verify(chk))) return chk;
    } catch (e) { console.log("calMutate retry", String(e && e.message)); }
    await sleepMs(350 * (i + 1));
  }
  return null;
};
const calAddRsvp = (env, evId, entry) => calMutate(env, evId, (ev) => { ev.rsvps = (ev.rsvps || []).filter((r) => r.id !== entry.id).concat([entry]); }, (chk) => (chk.rsvps || []).some((r) => r.id === entry.id));
const calDropRsvp = (env, evId, pid) => calMutate(env, evId, (ev) => { ev.rsvps = (ev.rsvps || []).filter((r) => r.id !== pid); }, (chk) => !(chk.rsvps || []).some((r) => r.id === pid));
// A person's saved form answers live in one KV map per event; same fresh-write-verify treatment. Returns the merged map.
const calFormPut = (env, evId, pid, entry) => calWithLock(env, "calform:" + evId, () => calFormPutRaw(env, evId, pid, entry));
const calFormPutRaw = async (env, evId, pid, entry) => {
  for (let i = 0; i < 5; i++) {
    try {
      let map = {}; try { map = JSON.parse((await env.SITE_DATA.get(calFormKey(evId))) || "{}") || {}; } catch {}
      map[pid] = entry; await env.SITE_DATA.put(calFormKey(evId), JSON.stringify(map));
      let chk = {}; try { chk = JSON.parse((await env.SITE_DATA.get(calFormKey(evId))) || "{}") || {}; } catch {}
      if (chk[pid]) return chk;
    } catch (e) { console.log("calFormPut retry", String(e && e.message)); }
    await sleepMs(350 * (i + 1));
  }
  return { [pid]: entry };
};
// Someone left (or was removed): free their spot, then move the first people on the waitlist up and tell them.
const calPromote = async (env, ctx, evId) => {
  try {
    const ev0 = (await readClubCal(env)).find((e) => e.id === evId); if (!ev0 || ev0.tbd) return;
    const waiters = (ev0.rsvps || []).filter((r) => r.status === "waitlist").sort((a, b) => (a.at || 0) - (b.at || 0)), moved = [];
    for (const r of waiters) { if (!calCap(ev0)) { moved.push(r.id); continue; } if (!(await calClaimSpot(env, ev0, r.id, false))) break; moved.push(r.id); } // no limit any more: everyone waiting is in
    if (!moved.length) return;
    const ev = await calMutate(env, evId, (e) => { for (const r of e.rsvps || []) if (moved.includes(r.id) && r.status === "waitlist") r.status = "going"; });
    for (const id of moved) if (!String(id).startsWith("g:") && ev) ctx.waitUntil(sendPushToUser(env, id, { title: "A spot opened up! 🎉", body: `You're now going to ${ev.title} (${ev.date}).`, url: `/#/form/${ev.slug || ev.id}`, cat: "events" }).catch(() => {}));
  } catch (e) { console.error("calPromote failed", String(e && e.message)); }
};
const calAfterRemoval = async (env, ctx, evId, pid) => { await calReleaseSpot(env, evId, pid); await calPromote(env, ctx, evId); };
// Automatic reminders (run from the hourly cron, Toronto 8am–8pm): 2 days before and the morning of, to everyone going who has the app/push on.
// A few people per run (each push costs several subrequests) with progress kept in KV, so a big event is covered within a few hours.
const calSendReminders = async (env, ctx) => {
  const hr = Number(new Date().toLocaleString("en-CA", { timeZone: "America/Toronto", hour: "2-digit", hour12: false })) % 24;
  if (hr < 8 || hr >= 20) return;
  const todayT = new Date().toLocaleDateString("en-CA", { timeZone: "America/Toronto" });
  const soonT = new Date(Date.parse(todayT + "T12:00:00Z") + 2 * 86400000).toISOString().slice(0, 10);
  let budget = 10;
  for (const ev of await readClubCal(env)) {
    if (budget <= 0) break;
    if (ev.tbd || !ev.date || (ev.date !== todayT && ev.date !== soonT)) continue;
    const kind = ev.date === todayT ? "day" : "soon", key = `evrem:${ev.id}:${kind}`;
    let st = {}; try { st = JSON.parse((await env.SITE_DATA.get(key)) || "{}") || {}; } catch {}
    if (st.done) continue;
    const sent = new Set(st.sent || []);
    const todo = (ev.rsvps || []).filter((r) => r.status === "going" && !String(r.id).startsWith("g:") && !sent.has(r.id)).slice(0, budget);
    for (const r of todo) {
      const owes = ev.form && ev.form.payment && !r.paid;
      const when = kind === "day" ? "today" : "in 2 days";
      try { await sendPushToUser(env, r.id, { title: kind === "day" ? `Today: ${ev.title} 🎉` : `${ev.title} is ${when}`, body: [ev.time ? `⏰ ${ev.time}` : "", ev.place ? `📍 ${ev.place}` : "", owes ? "💳 Don't forget to pay — details on the event page" : ""].filter(Boolean).join(" · ") || "Tap for the details", url: `/#/form/${ev.slug || ev.id}`, cat: "events" }); } catch {}
      sent.add(r.id); budget--;
    }
    const left = (ev.rsvps || []).filter((r) => r.status === "going" && !String(r.id).startsWith("g:") && !sent.has(r.id)).length;
    await env.SITE_DATA.put(key, JSON.stringify({ sent: [...sent], done: left === 0 }), { expirationTtl: 259200 });
  }
};
const calFields = (b) => ({ mapUrl: b.mapUrl ? (isGoogleMapsUrl(b.mapUrl) || "") : "", title: cleanCalText(b.title, 80), date: String(b.date || ""), time: cleanCalText(b.time, 30), place: cleanCalText(b.place, 200), rsvpBy: /^\d{4}-\d{2}-\d{2}$/.test(String(b.rsvpBy || "")) ? String(b.rsvpBy) : "", desc: String(b.desc || "").replace(/[\x00-\x08\x0b-\x1f\x7f]/g, " ").trim().slice(0, 3000), capacity: Math.max(0, Math.min(5000, parseInt(b.capacity, 10) || 0)) });
const isValidDateString = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + "T00:00:00Z"));

const dateRange = (startDate, endDate) => {
  const out = [];
  let cur = new Date(startDate + "T00:00:00Z");
  const end = new Date(endDate + "T00:00:00Z");
  while (cur <= end && out.length < 31) {
    out.push(cur.toISOString().slice(0, 10));
    cur = new Date(cur.getTime() + 86400000);
  }
  return out;
};

const sanitizeEventSlots = (input, event) => {
  if (!Array.isArray(input)) return [];
  const validDates = new Set(event.dates);
  const out = new Set();
  for (const slot of input) {
    if (typeof slot !== "string") continue;
    const [date, halfHourStr] = slot.split("|");
    const halfHour = Number(halfHourStr);
    if (!validDates.has(date)) continue;
    if (!Number.isInteger(halfHour) || halfHour < event.startHour * 2 || halfHour >= event.endHour * 2) continue;
    out.add(`${date}|${halfHour}`);
  }
  return [...out];
};

// ---- In-site calendar event editor: commits straight to GitHub, same as Decap CMS ----
const GITHUB_OWNER = "lujaneyaffa";
const GITHUB_REPO = "4dasistas";
const GITHUB_API = "https://api.github.com";

// Blocks path-traversal (no "/" or "\" means an id can never introduce extra path
// segments) and control chars, rather than allowlisting characters — real event ids
// contain all sorts of emoji, curly apostrophes, etc. that a narrow allowlist would reject.
const CALENDAR_ID_RE = /^[^/\\\x00-\x1f]{1,150}$/;
const calendarFilePath = (id) => `data/calendar/${id}.json`;
const CALENDAR_SECTIONS = ["sports", "activities", "functions", "trips", "mosqueprograms", "supportprograms"];

const slugify = (title) => {
  const slug = String(title || "")
    .toLowerCase()
    .trim()
    .replace(/['’‘"“”]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return slug || "event";
};

const b64EncodeUnicode = (str) => btoa(unescape(encodeURIComponent(str)));
const b64DecodeUnicode = (str) => decodeURIComponent(escape(atob(str.replace(/\n/g, ""))));

const githubHeaders = (env) => ({
  Authorization: `Bearer ${env.GITHUB_TOKEN}`,
  "User-Agent": "4dasistas-admin-editor",
  Accept: "application/vnd.github+json",
});

const githubGetFile = async (env, path) => {
  const res = await fetch(
    `${GITHUB_API}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`,
    { headers: githubHeaders(env) }
  );
  if (!res.ok) return null;
  const data = await res.json();
  return { sha: data.sha, content: JSON.parse(b64DecodeUnicode(data.content)) };
};

const githubPutFile = async (env, path, content, sha, message) => {
  return fetch(`${GITHUB_API}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`, {
    method: "PUT",
    headers: { ...githubHeaders(env), "Content-Type": "application/json" },
    body: JSON.stringify({
      message,
      content: b64EncodeUnicode(JSON.stringify(content, null, 2) + "\n"),
      sha,
      branch: "main",
      committer: { name: "4DASISTAS Site Admin", email: "admin@4dasistas.ca" },
    }),
  });
};

const githubDeleteFile = async (env, path, sha, message) => {
  return fetch(`${GITHUB_API}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`, {
    method: "DELETE",
    headers: { ...githubHeaders(env), "Content-Type": "application/json" },
    body: JSON.stringify({
      message,
      sha,
      branch: "main",
      committer: { name: "4DASISTAS Site Admin", email: "admin@4dasistas.ca" },
    }),
  });
};

// A handful of pre-migration events kept their original (non-slug) id inside
// the file while the file itself was saved under a slugified name — e.g. id
// "MuslimahFarmerMarket" lives in muslimahfarmermarket.json. New events always
// have filename === id, so try that first and only fall back to the slug.
const resolveCalendarFile = async (env, id) => {
  const direct = calendarFilePath(id);
  let file = await githubGetFile(env, direct);
  if (file) return { file, path: direct };
  const slugPath = calendarFilePath(slugify(id));
  if (slugPath === direct) return null;
  file = await githubGetFile(env, slugPath);
  return file ? { file, path: slugPath } : null;
};

// ---- In-site resources/small-business editor: same GitHub-backed pattern as calendar events ----
const resourceFilePath = (id) => `data/resources/${id}.json`;
const RESOURCE_CATEGORIES = ["cafes", "shops", "restaurants", "beautycare", "wellness", "mentalhealth", "catering", "eventservices", "clothing", "legal", "communityorg"];

const resolveResourceFile = async (env, id) => {
  const direct = resourceFilePath(id);
  let file = await githubGetFile(env, direct);
  if (file) return { file, path: direct };
  const slugPath = resourceFilePath(slugify(id));
  if (slugPath === direct) return null;
  file = await githubGetFile(env, slugPath);
  return file ? { file, path: slugPath } : null;
};

const jsonResponse = (body, status = 200, corsHeaders = {}) => new Response(JSON.stringify(body), {
  status,
  headers: { "Content-Type": "application/json", ...corsHeaders },
});

const escapeHtml = (value) => String(value || "")
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#039;");

const torontoDate = () => new Intl.DateTimeFormat("en-CA", {
  timeZone: "America/Toronto", year: "numeric", month: "2-digit", day: "2-digit",
}).format(new Date());

const weekdayForDate = (dateString) => new Date(`${dateString}T00:00:00Z`).getUTCDay();
const weekdayNumbers = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };

// Monthly repeats: Nth (or last) weekday of the month, or a fixed day of the month.
const monthlyRuleMatches = (item, dateString) => {
  if (item.recurFrequency !== "monthly") return false;
  const start = item.recurStart || item.calDate || item.eventDate || "";
  if (start && dateString < start) return false;
  if (item.recurEnd && dateString > item.recurEnd) return false;
  const [y, m, d] = dateString.split("-").map(Number);
  if (item.monthlyType === "date") return d === Math.floor(Number(item.monthlyDate));
  const wd = weekdayNumbers[String(item.monthlyDay || "").toLowerCase()];
  if (wd === undefined || weekdayForDate(dateString) !== wd) return false;
  if (item.monthlyWeek === "last") return d + 7 > new Date(Date.UTC(y, m, 0)).getUTCDate();
  return Math.ceil(d / 7) === Number(item.monthlyWeek);
};

const eventIsOnDate = (item, dateString) => {
  if (item.calDate === dateString || item.eventDate === dateString) return true;
  if (monthlyRuleMatches(item, dateString)) return true;
  if (!Array.isArray(item.days) || !item.days.length) return false;
  if (item.recurStart && dateString < item.recurStart) return false;
  if (item.recurEnd && dateString > item.recurEnd) return false;
  return item.days.some(day => weekdayNumbers[String(day).toLowerCase()] === weekdayForDate(dateString));
};

const readTodayEvents = async (env) => {
  const origin = env.SITE_ORIGIN || "https://4dasistas.ca";
  const dateString = torontoDate();
  const events = [];
  for (const file of EVENT_FILES) {
    const response = await fetchSiteFile(env, `/data/${file}.json`);
    if (!response.ok) continue;
    const data = await response.json();
    for (const item of data.items || []) {
      if (file === "trips" && item.tripType === "international") continue;
      if (eventIsOnDate(item, dateString)) events.push({ ...item, category: file });
    }
  }
  return { dateString, events };
};

export default {
  async fetch(request, env, ctx) {
    const ADMIN_PASSWORD = env.ADMIN_PASSWORD; // REQUIRED Worker secret — auth fails closed when unset

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS, DELETE",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Guest-Id, X-Guest-Name",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // ---- Review page (opened from the notification email): edit / accept / deny a submitted event or resource ----
    const reviewPageMatch = path.match(/^\/review\/(event|resource)\/([^/]+)\/?$/);
    if (reviewPageMatch && request.method === "GET") {
      const kind = reviewPageMatch[1], id = decodeURIComponent(reviewPageMatch[2]);
      const sig = url.searchParams.get("sig") || "";
      const page = (body, status = 200) => new Response(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>Review · 4DASISTAS</title><style>*{box-sizing:border-box}body{margin:0;background:#fef7f4;color:#373d3b;font-family:-apple-system,Segoe UI,Arial,sans-serif;line-height:1.55}header{background:#ce8491;border-bottom:2px solid #76220b;padding:18px 16px;text-align:center}header a{font-family:Georgia,'Times New Roman',serif;font-size:28px;letter-spacing:4px;font-weight:700;color:#fff;text-decoration:none}header div{font-size:11px;letter-spacing:1.6px;color:#fde9ea;margin-top:2px}main{max-width:560px;margin:18px auto 60px;padding:22px 20px;background:#fff;border:2px solid #76220b;border-radius:20px;box-shadow:4px 4px 0 #76220b;width:calc(100% - 24px)}h1{font-size:22px;margin:0 0 6px;color:#76220b}label{display:block;font-size:13px;color:#776867;margin:14px 0 4px}input,select{width:100%;padding:12px;border-radius:12px;border:2px solid #76220b;font-size:16px;background:#fff;font-family:inherit}input[type=checkbox]{width:22px;height:22px;margin-right:8px;vertical-align:middle}.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}button{flex:1;min-height:50px;border:2px solid #76220b;border-radius:999px;font-size:16px;font-weight:700;color:#fff;cursor:pointer;font-family:inherit}.ok{background:#2a7a4a}.no{background:#b3261e}.note{padding:12px 14px;border-radius:14px;background:#f2d8d7;color:#76220b;margin:14px 0;white-space:pre-wrap}.msg{margin-top:16px;font-weight:700}a{color:#76220b}</style></head><body><header><a href="/">4DASISTAS</a><div>CLUBS · EVENTS · SQUADS · GTA</div></header><main>${body}</main></body></html>`, { status, headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex" } });
      if (!sameSig(sig, await reviewSig(env, kind, id))) return page("<h1>Link not valid</h1><p>This review link isn't valid. Open the site, log in as admin and use the Submitted events / resources card instead.</p>", 403);
      const raw = await env.SITE_DATA.get(`${kind === "event" ? "eventsug" : "ressug"}:${id}`);
      if (!raw) return page("<h1>Already handled</h1><p>This submission has already been accepted, denied or dismissed.</p>");
      let sug; try { sug = JSON.parse(raw); } catch { return page("<h1>Could not read that submission</h1>", 500); }
      const a = url.searchParams.get("a") || "";
      const e = escapeHtml;
      const fields = kind === "event"
        ? `<label>Event name</label><input id="f_title" value="${e(sug.name)}"><label>Date</label><input id="f_date" type="date" value="${e(sug.date)}"><label>City</label><input id="f_city" value="${e(sug.virtual ? "" : sug.city)}"><label><input id="f_virtual" type="checkbox" ${sug.virtual ? "checked" : ""}>Virtual event</label><label>Link</label><input id="f_link" value="${e(sug.link)}"><label>Show it under which Calendar tab?</label><select id="f_section">${[["functions", "Functions (markets, festivals, gatherings)"], ["activities", "Activities"], ["sports", "Sports"], ["trips", "Trips"], ["mosqueprograms", "Knowledge (mosque programs)"], ["supportprograms", "Support programs"]].map(([k, l]) => `<option value="${k}" ${k === (GENRE_TO_SECTION[sug.genre] || "functions") ? "selected" : ""}>${e(l)}</option>`).join("")}</select>`
        : `<label>Name</label><input id="f_title" value="${e(sug.title)}"><label>Type</label>${sug.type === "other" ? `<div class="note" style="margin:4px 0">They chose “Other”: <strong>${e(sug.typeOther || "")}</strong> — pick the closest type below.</div>` : ""}<select id="f_type">${sug.type === "other" ? '<option value="">Pick a type…</option>' : ""}${RESOURCE_CATEGORIES.map((k) => `<option value="${k}" ${k === sug.type ? "selected" : ""}>${e(k)}</option>`).join("")}</select><label>Link (Instagram / WhatsApp)</label><input id="f_link" value="${e(sug.link)}"><label>City</label><input id="f_city" value="${e(sug.virtual ? "" : sug.city)}"><label><input id="f_virtual" type="checkbox" ${sug.virtual ? "checked" : ""}>Virtual / online only</label>`;
      const genreNote = kind === "event" && sug.genre ? `<div class="note" style="margin:4px 0"><strong>Genre:</strong> ${e(sug.genre === "other" ? `Other — ${sug.genreOther || ""}` : sug.genre)}</div>` : "";
      const comments = genreNote + (sug.comments ? `<div class="note"><strong>Comments from the submitter</strong>\n${e(sug.comments)}</div>` : "");
      return page(`<h1>${kind === "event" ? "Event" : "Resource"} submitted</h1><p style="margin:0;color:#776867">Change anything below, then accept or deny.</p>${comments}${fields}<div class="row"><button class="ok" id="btnAccept">✅ Accept &amp; publish</button><button class="no" id="btnDeny">❌ Deny</button></div><div class="msg" id="msg"></div>
<script>
const KIND=${JSON.stringify(kind)},ID=${JSON.stringify(id)},SIG=${JSON.stringify(sig)},PRE=${JSON.stringify(a)};
const $=i=>document.getElementById(i);
function vals(){const o={title:$('f_title').value,link:$('f_link').value,city:$('f_city').value,virtual:$('f_virtual').checked};if(KIND==='event'){o.date=$('f_date').value;o.section=$('f_section').value}else o.type=$('f_type').value;return o}
async function act(action){
  if(action==='deny'&&!confirm('Deny and delete this submission?'))return;
  document.querySelectorAll('button').forEach(b=>b.disabled=true);$('msg').style.color='#373d3b';$('msg').textContent='Working…';
  try{const r=await fetch('/api/review/'+KIND+'/'+encodeURIComponent(ID),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sig:SIG,action,fields:vals()})});const d=await r.json().catch(()=>({}));
    if(!r.ok)throw new Error(d.error||'Something went wrong');
    $('msg').style.color=action==='accept'?'#2a7a4a':'#b3261e';$('msg').textContent=action==='accept'?'Accepted — it will be live on the site in about a minute.':'Denied and removed.';
  }catch(e){$('msg').style.color='#b3261e';$('msg').textContent=e.message;document.querySelectorAll('button').forEach(b=>b.disabled=false)}
}
$('btnAccept').onclick=()=>act('accept');$('btnDeny').onclick=()=>act('deny');
if(PRE==='deny')$('btnDeny').scrollIntoView({block:'center'});if(PRE==='edit')$('f_title').focus();
</script>`);
    }
    const reviewActionMatch = path.match(/^\/api\/review\/(event|resource)\/([^/]+)\/?$/);
    if (reviewActionMatch && request.method === "POST") {
      const kind = reviewActionMatch[1], id = decodeURIComponent(reviewActionMatch[2]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!sameSig(body.sig, await reviewSig(env, kind, id))) return jsonResponse({ error: "This review link isn't valid" }, 403, corsHeaders);
      const kvKey = `${kind === "event" ? "eventsug" : "ressug"}:${id}`;
      const raw = await env.SITE_DATA.get(kvKey);
      if (!raw) return jsonResponse({ error: "Already handled" }, 404, corsHeaders);
      if (body.action === "deny") { await env.SITE_DATA.delete(kvKey); return jsonResponse({ ok: true }, 200, corsHeaders); }
      if (body.action !== "accept") return jsonResponse({ error: "Unknown action" }, 400, corsHeaders);
      if (!env.GITHUB_TOKEN) return jsonResponse({ error: "Server misconfigured: GITHUB_TOKEN is not set" }, 500, corsHeaders);
      let sug; try { sug = JSON.parse(raw); } catch { return jsonResponse({ error: "Could not read that submission" }, 500, corsHeaders); }
      const f = body.fields && typeof body.fields === "object" ? body.fields : {};
      const clean = (v, max) => String(v || "").replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
      const title = clean(f.title, 120);
      const virtual = f.virtual === true;
      const city = virtual ? "Virtual" : clean(f.city, 60);
      let link = "";
      try { const u = new URL(String(f.link || "").trim()); if (u.protocol === "https:" || u.protocol === "http:") link = u.href.slice(0, 500); } catch {}
      if (title.length < 2) return jsonResponse({ error: "Please add a name" }, 400, corsHeaders);
      if (!link) return jsonResponse({ error: "Please add a valid link (https://…)" }, 400, corsHeaders);
      if (city.length < 2) return jsonResponse({ error: "Please add the city (or tick Virtual)" }, 400, corsHeaders);
      let content, filePath, baseSlug;
      if (kind === "event") {
        const date = clean(f.date, 10);
        if (!isValidDateString(date)) return jsonResponse({ error: "Please pick a valid date" }, 400, corsHeaders);
        if (!CALENDAR_SECTIONS.includes(f.section)) return jsonResponse({ error: "Please pick a Calendar tab" }, 400, corsHeaders);
        const longDate = new Date(date + "T12:00:00Z").toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric", timeZone: "UTC" });
        content = { title, section: f.section, eventDate: date, date: longDate, location: city, virtual, link, desc: sug.comments || "" };
        baseSlug = slugify(title);
        filePath = calendarFilePath;
      } else {
        if (!RESOURCE_CATEGORIES.includes(f.type)) return jsonResponse({ error: "Please pick a type" }, 400, corsHeaders);
        const isIg = /(^|\.)instagram\.com$/i.test(new URL(link).hostname.replace(/^www\./, ""));
        content = { title, type: f.type, category: f.type, location: city, desc: sug.comments || "", ownedBy: "Community submission", ...(isIg ? { instagram: link } : { website: link }) };
        baseSlug = slugify(title);
        filePath = resourceFilePath;
      }
      if (!CALENDAR_ID_RE.test(baseSlug)) return jsonResponse({ error: "Could not derive a valid id from the name" }, 400, corsHeaders);
      let finalSlug = baseSlug;
      for (let n = 2; await githubGetFile(env, filePath(finalSlug)); n++) {
        if (n > 50) return jsonResponse({ error: "Could not find a unique id for this name" }, 500, corsHeaders);
        finalSlug = `${baseSlug}-${n}`;
      }
      const res = await githubPutFile(env, filePath(finalSlug), content, undefined, `Create "${title}" from a community submission (approved via email)`);
      if (!res.ok) return jsonResponse({ error: "GitHub commit failed", detail: (await res.text().catch(() => "")).slice(0, 200) }, 502, corsHeaders);
      await env.SITE_DATA.delete(kvKey);
      return jsonResponse({ ok: true, id: finalSlug }, 200, corsHeaders);
    }

    // Clean shareable links for the two public forms: 4dasistas.ca/submit-event and 4dasistas.ca/add-resource. Like the club
    // links, a chat app's preview crawler reads THIS page's tags (it never runs JS / sees a #hash); a person who clicks is bounced
    // straight into the normal site, on the right form, with the full navigation around it.
    const shareFormMatch = path.match(/^\/(submit-event|add-resource)\/?$/);
    if (shareFormMatch && request.method === "GET") {
      const isEvent = shareFormMatch[1] === "submit-event";
      const title = isEvent ? "Submit an event — 4DASISTAS" : "Add a resource — 4DASISTAS";
      const desc = isEvent ? "Know an event we should add to the 4DASISTAS calendar? Send it in — an admin reviews every one." : "Know a business or resource we should add to the 4DASISTAS directory? Send it in — an admin reviews every one.";
      const pageUrl = `https://4dasistas.ca/${shareFormMatch[1]}`;
      const dest = `/#/${shareFormMatch[1]}`;
      const html = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(desc)}">
<meta property="og:title" content="${escapeHtml(title)}">
<meta property="og:description" content="${escapeHtml(desc)}">
<meta property="og:image" content="https://4dasistas.ca/assets/og-4ds.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:url" content="${escapeHtml(pageUrl)}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="https://4dasistas.ca/assets/og-4ds.png">
<meta http-equiv="refresh" content="0; url=${escapeHtml(dest)}">
<script>location.replace(${JSON.stringify(dest)});</script>
</head><body>Opening 4DASISTAS… <a href="${escapeHtml(dest)}">Tap here</a> if nothing happens.</body></html>`;
      return new Response(html, { headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store, must-revalidate", ...corsHeaders } });
    }
    // A club's shared link (4dasistas.ca/clubs/<slug>) gets its own preview title/description/image when
    // pasted into Instagram/WhatsApp/iMessage. Hash routes (#/clubs/<slug>) can't do this — a share-card
    // crawler fetches the URL and reads its HTML, it never runs JS to see location.hash. This page is a
    // real, crawlable path only for that purpose; a real visitor gets bounced straight into the app.
    const clubPathMatch = path.match(/^\/clubs\/([a-z0-9-]+)\/?$/);
    if (clubPathMatch && request.method === "GET") {
      const club = (await readClubRoster(env)).find((c) => c.slug === clubPathMatch[1]);
      const meta = club ? { title: club.title, emoji: club.emoji || "✨", desc: club.desc || "" } : null;
      if (meta) {
        const title = `${meta.emoji} ${meta.title} Club — 4DASISTAS`;
        const pageUrl = `https://4dasistas.ca/clubs/${clubPathMatch[1]}`;
        const dest = `/#/clubs/${clubPathMatch[1]}`;
        const html = `<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(meta.desc)}">
<meta property="og:title" content="${escapeHtml(title)}">
<meta property="og:description" content="${escapeHtml(meta.desc)}">
<meta property="og:image" content="https://4dasistas.ca/assets/og-4ds.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:url" content="${escapeHtml(pageUrl)}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="https://4dasistas.ca/assets/og-4ds.png">
<meta name="twitter:title" content="${escapeHtml(title)}">
<meta name="twitter:description" content="${escapeHtml(meta.desc)}">
<meta http-equiv="refresh" content="0; url=${escapeHtml(dest)}">
<script>location.replace(${JSON.stringify(dest)});</script>
</head><body>Opening the ${escapeHtml(meta.title)} Club… <a href="${escapeHtml(dest)}">Tap here</a> if nothing happens.</body></html>`;
        return new Response(html, { headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store, must-revalidate", ...corsHeaders } });
      }
    }

    // Public, live club roster — the frontend uses this instead of (or as a freshness check against)
    // the static data/clubs.json, so an admin's add/edit/remove shows up immediately, not only after
    // the next full site deploy.
    // Public, non-sensitive: which Worker build is live, and whether the club-file sync is healthy (used to diagnose deploys).
    if (path === "/api/health" && request.method === "GET") {
      const roster = await readClubRoster(env);
      return jsonResponse({ build: WORKER_BUILD, d1Bound: !!env.DB, clubs: roster.map((c) => c.title), clubFile: _fileClubsStatus }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    if (path === "/api/clubs" && request.method === "GET") {
      return jsonResponse({ clubs: await readClubRoster(env) }, 200, corsHeaders);
    }

    const readSubs = async () => { try { const a = JSON.parse((await env.SITE_DATA.get(SUBSCRIBER_INDEX_KEY)) || "[]"); return Array.isArray(a) ? a : []; } catch { return []; } };
    const subPage = (title, body) => new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} — 4DASISTAS</title></head><body style="margin:0;background:#fef7f4;font-family:Arial,Helvetica,sans-serif;color:#373d3b"><div style="background:#ce8491;padding:18px;text-align:center;color:#fff;font:700 26px Georgia,serif;letter-spacing:.12em">4DASISTAS</div><div style="max-width:480px;margin:22px auto;padding:0 16px"><div style="background:#fff;border:2px solid #76220b;border-radius:18px;padding:20px">${body}</div></div></body></html>`, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...corsHeaders } });
    const subBtn = (label, action, token, bg, color) => `<form method="POST" action="/api/manage-subscription" style="margin:10px 0 0"><input type="hidden" name="token" value="${escapeHtml(token)}"><input type="hidden" name="action" value="${action}"><button style="width:100%;padding:13px;border-radius:999px;border:2px solid #76220b;background:${bg};color:${color};font:700 16px Arial;cursor:pointer">${label}</button></form>`;
    if (path === "/api/subscribe" && request.method === "POST") {
      let email;
      try { email = String((await request.json()).email || "").trim().toLowerCase(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonResponse({ error: "Valid email required" }, 400, corsHeaders);
      const index = await readSubs();
      const existing = index.find(subscriber => subscriber.email === email);
      if (existing) { if (existing.paused) { delete existing.paused; await env.SITE_DATA.put(SUBSCRIBER_INDEX_KEY, JSON.stringify(index)); } return jsonResponse({ ok: true }, 200, corsHeaders); }
      const token = crypto.randomUUID();
      index.push({ email, token, createdAt: Date.now() });
      await env.SITE_DATA.put(SUBSCRIBER_INDEX_KEY, JSON.stringify(index));
      return jsonResponse({ ok: true }, 201, corsHeaders);
    }
    // One-tap unsubscribe (the email's footer link) pauses the daily list and points to the manage page, where it can be turned back on or the email removed.
    if (path === "/api/unsubscribe" && request.method === "GET") {
      const token = url.searchParams.get("token") || "";
      const index = await readSubs(), me = index.find((x) => x.token === token);
      if (me) { me.paused = true; await env.SITE_DATA.put(SUBSCRIBER_INDEX_KEY, JSON.stringify(index)); }
      return subPage("Unsubscribed", `<h2 style="margin:0 0 8px">You're unsubscribed ✅</h2><p>You won't get the daily “What's on today” email any more.</p>${me ? `<p style="margin:14px 0 0"><a href="/api/manage-subscription?token=${encodeURIComponent(token)}" style="color:#76220b;font-weight:700">Changed your mind? Manage your subscription →</a></p>` : ""}`);
    }
    if (path === "/api/manage-subscription" && (request.method === "GET" || request.method === "POST")) {
      let token = url.searchParams.get("token") || "", action = "";
      if (request.method === "POST") { try { const f = await request.formData(); token = String(f.get("token") || token); action = String(f.get("action") || ""); } catch {} }
      const index = await readSubs(), me = index.find((x) => x.token === token);
      if (!me) return subPage("Subscription", `<h2 style="margin:0 0 8px">We couldn't find that subscription</h2><p>It may already have been removed. You can subscribe again any time from <a href="/" style="color:#76220b;font-weight:700">4dasistas.ca</a>.</p>`);
      let note = "";
      if (action === "pause") { me.paused = true; note = "Paused — you won't get the daily email."; }
      else if (action === "resume") { delete me.paused; note = "You're subscribed again 🎉"; }
      else if (action === "delete") {
        await env.SITE_DATA.put(SUBSCRIBER_INDEX_KEY, JSON.stringify(index.filter((x) => x.token !== token)));
        return subPage("Removed", `<h2 style="margin:0 0 8px">Your email was removed 🗑️</h2><p>We've deleted ${escapeHtml(me.email)} from the daily list.</p>`);
      }
      if (action) await env.SITE_DATA.put(SUBSCRIBER_INDEX_KEY, JSON.stringify(index));
      return subPage("Manage subscription", `<h2 style="margin:0 0 6px">Manage your subscription ⚙️</h2><p style="margin:0 0 4px">Daily “What's on today” email to <strong>${escapeHtml(me.email)}</strong></p><p style="margin:0 0 10px">Status: <strong style="color:${me.paused ? "#b3261e" : "#2a7a4a"}">${me.paused ? "Paused" : "Subscribed"}</strong></p>${note ? `<p style="background:#e6f4ea;border-radius:10px;padding:8px 10px">${escapeHtml(note)}</p>` : ""}${me.paused ? subBtn("Turn it back on", "resume", token, "#ce8491", "#fff") : subBtn("Pause the daily email", "pause", token, "#fff", "#76220b")}${subBtn("Remove my email completely", "delete", token, "#fdecea", "#b3261e")}`);
    }

    // ---- Club Members Schedule (public sign-in/profile/event-availability routes) ----

    const cmMembersMatch = path.match(/^\/api\/clubs\/([^/]+)\/members\/?$/);
    const userByIdMatch = path.match(/^\/api\/users\/([^/]+)\/?$/);
    const cmEventsMatch = path.match(/^\/api\/clubs\/([^/]+)\/events\/?$/);
    const cmEventResponsesMatch = path.match(/^\/api\/clubs\/([^/]+)\/events\/([^/]+)\/responses\/?$/);
    const cmEventResponseByMemberMatch = path.match(/^\/api\/clubs\/([^/]+)\/events\/([^/]+)\/responses\/([^/]+)\/?$/);

    // Global sign-in: username+PIN identifies one person, independent of any club.
    if (path === "/api/login" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      let username = sanitizeUsername(body.username);
      const pin = String(body.pin || "").trim();
      // A phone number works as a login name too (it's resolved to the account's username, so the same rate limits apply).
      { const rawU = String(body.username || "").trim();
        if (/^[\d\s().+-]{7,20}$/.test(rawU) && bmDigits(rawU).length >= 10) {
          const r = await usernameForPhone(env, bmDigits(rawU), ctx);
          if (r === "ambiguous") return jsonResponse({ error: "More than one account uses that number — please log in with your username" }, 400, corsHeaders);
          if (r) username = r;
        } }
      if (!username || !pin) return jsonResponse({ error: "Username (or phone number) and PIN are required" }, 400, corsHeaders);

      // Usernames are now predictable (firstname.initial), and PINs are only 4 digits - without a
      // limit here, an unlimited number of guesses would make the PIN effectively no protection at
      // all. Cap both by IP (stops one attacker hammering many accounts) and by the username itself
      // (stops many IPs/a botnet focusing on one account) - every attempt counts, not just failures,
      // so the limit can't be probed around by checking which responses increment it.
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const hourSlot = Math.floor(Date.now() / 3600000);
      const loginIpKey = `loginrate:ip:${ip}:${hourSlot}`;
      const loginUserKey = `loginrate:user:${username}:${hourSlot}`;
      const nIp = await rateTouch(env, loginIpKey, 3700), nUser = nIp === null ? null : await rateTouch(env, loginUserKey, 3700);
      if (nIp !== null && nUser !== null) { // D1 counters (no KV writes)
        if (nIp > LOGIN_MAX_ATTEMPTS_PER_IP_PER_HOUR) return jsonResponse({ error: "Too many login attempts from this connection — please try again in an hour" }, 429, corsHeaders);
        if (nUser > LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_HOUR) return jsonResponse({ error: "Too many attempts for this account — please try again in an hour, or ask an admin to reset your PIN" }, 429, corsHeaders);
      } else {
      const [loginIpCount, loginUserCount] = await Promise.all([env.SITE_DATA.get(loginIpKey), env.SITE_DATA.get(loginUserKey)]);
      if (Number(loginIpCount || 0) >= LOGIN_MAX_ATTEMPTS_PER_IP_PER_HOUR) {
        return jsonResponse({ error: "Too many login attempts from this connection — please try again in an hour" }, 429, corsHeaders);
      }
      if (Number(loginUserCount || 0) >= LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_HOUR) {
        return jsonResponse({ error: "Too many attempts for this account — please try again in an hour, or ask an admin to reset your PIN" }, 429, corsHeaders);
      }
      await Promise.all([
        env.SITE_DATA.put(loginIpKey, String(Number(loginIpCount || 0) + 1), { expirationTtl: 3700 }),
        env.SITE_DATA.put(loginUserKey, String(Number(loginUserCount || 0) + 1), { expirationTtl: 3700 }),
      ]);
      }

      const userId = await findUserIdByUsername(env, username);
      const user = userId ? await readUser(env, userId) : null;
      if (!user || user.pinHash !== await sha256Hex(pin)) {
        return jsonResponse({ error: "Username or PIN is incorrect" }, 401, corsHeaders);
      }
      user.lastLoginAt = Date.now();
      user.lastSeenAt = user.lastLoginAt;
      if (!(await touchMember(env, user.id, true))) await writeUser(env, user); // (D1 when available — no KV write)
      const token = await createMemberSession(env, user.id);
      const clubs = await allClubIdsContaining(env, user.id);
      return jsonResponse({ ...publicUser(user), clubs, waitlist: visibleWaitlist(user, clubs), token }, 200, corsHeaders);
    }

    // Public self-signup (Sign Up form): creates the account, joins the chosen club, and signs them in.
    if (path === "/api/signup" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const name = String(body.name || "").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 60);
      const pin = String(body.pin || "").trim();
      const clubId = String(body.clubId || "");
      if (!name) return jsonResponse({ error: "Please enter your name" }, 400, corsHeaders);
      const username = await generateUniqueUsername(env, name);
      if (!username) return jsonResponse({ error: "Please enter your first name and last initial (e.g. Amina K.)" }, 400, corsHeaders);
      // The SAME person signing up again (forgot she already has a login, or lost her PIN) used to silently get
      // ayana.s2, ayana.s3 ... — a pile of duplicate profiles. Refuse an identical name and point her at log in.
      if (username !== usernameBaseFromName(name)) {
        const norm = (n) => String(n || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        {
          if ((await listAllUsers(env)).some((u) => norm(u.name) === norm(name))) {
            return jsonResponse({ error: `There's already a profile for ${name}. Please log in instead — if you forgot your PIN, message an admin on Instagram and they'll reset it.` }, 409, corsHeaders);
          }
        }
      }
      if (!/^\d{4}$/.test(pin)) return jsonResponse({ error: "PIN must be exactly 4 digits" }, 400, corsHeaders);
      const clubIds = new Set((await readClubRoster(env)).map((c) => c.id));
      // clubId is optional - someone who already told us their club picks some other way (a paper/DM
      // form, or they're just not ready to pick yet) can create a login with no club attached; an
      // admin assigns their club(s) afterward from the member-edit screen.
      if (clubId && !clubIds.has(clubId)) return jsonResponse({ error: "Please pick a club from the list" }, 400, corsHeaders);

      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const ipKey = `signuprate:${ip}:${Math.floor(Date.now() / 3600000)}`;
      const dayKey = `signupday:${new Date().toISOString().slice(0, 10)}`;
      const [ipCount, dayCount] = await Promise.all([env.SITE_DATA.get(ipKey), env.SITE_DATA.get(dayKey)]);
      if (Number(ipCount || 0) >= SIGNUP_MAX_PER_IP_PER_HOUR) return jsonResponse({ error: "Too many sign-ups from this connection — please try again in an hour" }, 429, corsHeaders);
      if (Number(dayCount || 0) >= SIGNUP_MAX_PER_DAY) return jsonResponse({ error: "Sign-ups are very busy right now — please message us on Instagram" }, 429, corsHeaders);

      if (await findUserIdByUsername(env, username)) return jsonResponse({ error: "That login was just taken — please try submitting again" }, 409, corsHeaders);

      const waitlist = clubId ? [...new Set((Array.isArray(body.waitlist) ? body.waitlist : []).map(String))].filter((id) => clubIds.has(id) && id !== clubId).slice(0, 1) : []; // 2 clubs total: the #1 pick (requested) + one on standby
      const user = { id: crypto.randomUUID(), name, username, pinHash: await sha256Hex(pin), photo: null, waitlist, createdAt: Date.now() };
      user.lastLoginAt = user.createdAt; user.lastSeenAt = user.createdAt;
      { const sf = sanitizeSignupForm(body.form, "site"); if (sf) user.form = sf; }
      const phone = sanitizePhone(body.phone);
      if (phone) user.phone = phone;
      await writeUser(env, user);
      await reserveUsername(env, username, user.id);
      _memberSearchCache = null;
      // Signing up no longer drops anyone straight into a club - their #1 pick becomes a request an admin
      // approves (the account itself, and the form that goes to organizers, are unchanged).
      if (clubId) {
        await env.SITE_DATA.put(joinReqKey(clubId, user.id), JSON.stringify({ at: Date.now() }));
        const club = (await readClubRoster(env)).find((c) => c.id === clubId);
        if (club) notifyAdminOfJoinRequest(env, ctx, user, club);
      } else {
        // signed up without asking for a club: still tell the admin there's a new member (the join-request email covers the other case)
        sendAdminEmail(env, ctx, `New member: ${user.name}`, emailShell(env, { emoji: "🎉", title: "New member signed up", preheader: `${user.name} just created an account`,
          body: `<p style="margin:0 0 6px"><strong>${escapeHtml(user.name)}</strong> <span style="color:#776867">@${escapeHtml(user.username)}</span> just created an account.</p>${user.phone ? `<p style="margin:0 0 6px">📞 ${escapeHtml(user.phone)}</p>` : ""}<p style="margin:0 0 6px;color:#776867">They haven't asked for a club yet.</p><p style="margin:16px 0 4px">${emailBtn((env.SITE_ORIGIN || "https://4dasistas.ca") + "/#/admin", "Open the admin page →")}</p>` }));
      }
      await Promise.all([
        env.SITE_DATA.put(ipKey, String(Number(ipCount || 0) + 1), { expirationTtl: 3700 }),
        env.SITE_DATA.put(dayKey, String(Number(dayCount || 0) + 1), { expirationTtl: 90000 }),
      ]);
      const token = await createMemberSession(env, user.id);
      const clubs = await allClubIdsContaining(env, user.id);
      return jsonResponse({ ...publicUser(user), clubs, pending: clubId ? [clubId] : [], waitlist: visibleWaitlist(user, clubs), token }, 201, corsHeaders);
    }

    if (cmMembersMatch && request.method === "GET") {
      // Full names + usernames: signed-in members, the main admin and club admins only (the PUBLIC list is /public-members: first names only).
      let allowed = false;
      { const ah = request.headers.get("Authorization") || "", tk = ah.startsWith("Bearer ") ? ah.slice(7) : "";
        if (tk && (await env.SITE_DATA.get(`membersession:${tk}`))) allowed = true;
        const ck = request.headers.get("Cookie") || "", sm = ck.match(/(?:^|;\s*)session=([^;]+)/), lm = ck.match(/(?:^|;\s*)leadsession=([^;]+)/);
        if (!allowed && sm && (await env.SITE_DATA.get(`session:${sm[1]}`))) allowed = true;
        if (!allowed && lm && (await env.SITE_DATA.get(`leadsession:${lm[1]}`))) allowed = true; }
      if (!allowed) return jsonResponse({ error: "Log in to see the member list" }, 401, corsHeaders);
      const clubId = decodeURIComponent(cmMembersMatch[1]);
      const members = await resolveClubMembers(env, clubId);
      return jsonResponse({ members: members.map(publicUser) }, 200, corsHeaders);
    }

    // Public self-signup is intentionally disabled — only the admin panel creates members
    // (POST /api/admin/club-members/:clubId), so profiles can never be created by a random visitor.

    if (userByIdMatch && request.method === "GET") {
      const userId = decodeURIComponent(userByIdMatch[1]);
      const user = await readUser(env, userId);
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      return jsonResponse(publicUser(user), 200, corsHeaders);
    }

    if (userByIdMatch && request.method === "PUT") {
      const userId = decodeURIComponent(userByIdMatch[1]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : String(body.token || "");
      const ok = await verifyMemberToken(env, userId, token);
      if (!ok) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      const user = await readUser(env, userId);
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      if (body.photo !== undefined) user.photo = sanitizePhoto(body.photo);
      // Members can change their own last name and username (first name stays; the username is the login, so it needs the current PIN).
      if (body.lastName !== undefined) {
        const last = String(body.lastName || "").replace(/[^\p{L}'’.\- ]/gu, "").replace(/\s+/g, " ").trim().slice(0, 30);
        if (last.length < 1) return jsonResponse({ error: "Please enter your last name (or just your initial)" }, 400, corsHeaders);
        const first = String(user.name || "").trim().split(/\s+/)[0] || "";
        user.name = `${first} ${last}`.trim();
      }
      if (body.username !== undefined && sanitizeUsername(body.username) !== user.username) {
        const nu = sanitizeUsername(body.username);
        if (!nu) return jsonResponse({ error: "Usernames are 2–40 letters, numbers, dots, dashes or underscores" }, 400, corsHeaders);
        if (!user.mustChangePin) {
          const k = `loginrate:user:${user.username}:${Math.floor(Date.now() / 3600000)}`;
          const n = Number(await env.SITE_DATA.get(k) || 0);
          if (n >= LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_HOUR) return jsonResponse({ error: "Too many attempts — please try again in an hour" }, 429, corsHeaders);
          await env.SITE_DATA.put(k, String(n + 1), { expirationTtl: 3700 });
          if (user.pinHash !== await sha256Hex(String(body.currentPin || "").trim())) return jsonResponse({ error: "Enter your current PIN to change your username" }, 401, corsHeaders);
        }
        const owner = await findUserIdByUsername(env, nu);
        if (owner && owner !== user.id) return jsonResponse({ error: "That username is already taken" }, 409, corsHeaders);
        await reserveUsername(env, nu, user.id);
        await releaseUsername(env, user.username);
        user.username = nu;
      }
      if (Array.isArray(body.notifOff)) user.notifOff = [...new Set(body.notifOff.map(String))].filter((c) => NOTIF_CATS.includes(c));
      if (body.newPin !== undefined) {
        const newPin = String(body.newPin || "").trim();
        if (!/^\d{4}$/.test(newPin)) return jsonResponse({ error: "PIN must be exactly 4 digits" }, 400, corsHeaders);
        // The forced first-sign-in change (starting PIN 1234) needs nothing more. A voluntary change must
        // prove the CURRENT pin, or anyone holding a signed-in-but-unattended phone could change it and
        // lock the owner out. Those guesses share the login rate limit's per-username counter, so this
        // route can't be used to brute-force the 4-digit PIN around /api/login's cap.
        if (!user.mustChangePin) {
          const changeUserKey = `loginrate:user:${user.username}:${Math.floor(Date.now() / 3600000)}`;
          const changeCount = Number(await env.SITE_DATA.get(changeUserKey) || 0);
          if (changeCount >= LOGIN_MAX_ATTEMPTS_PER_USERNAME_PER_HOUR) {
            return jsonResponse({ error: "Too many attempts — please try again in an hour, or ask an admin to reset your PIN" }, 429, corsHeaders);
          }
          await env.SITE_DATA.put(changeUserKey, String(changeCount + 1), { expirationTtl: 3700 });
          if (user.pinHash !== await sha256Hex(String(body.currentPin || "").trim())) {
            return jsonResponse({ error: "Current PIN is incorrect" }, 401, corsHeaders);
          }
        }
        user.pinHash = await sha256Hex(newPin);
        user.mustChangePin = false;
      }
      await writeUser(env, user);
      return jsonResponse(publicUser(user), 200, corsHeaders);
    }

    if (cmEventsMatch && request.method === "GET") {
      const clubId = decodeURIComponent(cmEventsMatch[1]);
      return jsonResponse({ events: await readClubEvents(env, clubId) }, 200, corsHeaders);
    }

    if (cmEventResponsesMatch && request.method === "GET") {
      const clubId = decodeURIComponent(cmEventResponsesMatch[1]);
      const eventId = decodeURIComponent(cmEventResponsesMatch[2]);
      const [members, raw] = await Promise.all([
        resolveClubMembers(env, clubId),
        env.SITE_DATA.get(clubEventResponsesKey(clubId, eventId)),
      ]);
      const responses = raw ? JSON.parse(raw) : {};
      const aggregate = {};
      const byMember = [];
      for (const member of members) {
        const slots = responses[member.id] || [];
        if (slots.length) byMember.push({ id: member.id, name: member.name, username: member.username, slots });
        for (const slot of slots) aggregate[slot] = (aggregate[slot] || 0) + 1;
      }
      return jsonResponse({ members: byMember, aggregate }, 200, corsHeaders);
    }

    if (cmEventResponseByMemberMatch && request.method === "PUT") {
      const clubId = decodeURIComponent(cmEventResponseByMemberMatch[1]);
      const eventId = decodeURIComponent(cmEventResponseByMemberMatch[2]);
      const userId = decodeURIComponent(cmEventResponseByMemberMatch[3]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : String(body.token || "");
      const ok = await verifyMemberToken(env, userId, token);
      if (!ok) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      const memberIds = await readClubMemberIds(env, clubId);
      if (!memberIds.includes(userId)) return jsonResponse({ error: "Not a member of this club" }, 403, corsHeaders);
      const events = await readClubEvents(env, clubId);
      const event = events.find(e => e.id === eventId);
      if (!event) return jsonResponse({ error: "Event not found" }, 404, corsHeaders);
      const key = clubEventResponsesKey(clubId, eventId);
      const raw = await env.SITE_DATA.get(key);
      const responses = raw ? JSON.parse(raw) : {};
      responses[userId] = sanitizeEventSlots(body.slots, event);
      await env.SITE_DATA.put(key, JSON.stringify(responses));
      return jsonResponse({ slots: responses[userId] }, 200, corsHeaders);
    }

    // ---- Event-idea boards ----
    const ideasListMatch = path.match(/^\/api\/clubs\/([^/]+)\/ideas\/?$/);
    const ideaVoteMatch = path.match(/^\/api\/clubs\/([^/]+)\/ideas\/([^/]+)\/vote\/?$/);
    const ideaOneMatch = path.match(/^\/api\/clubs\/([^/]+)\/ideas\/([^/]+)\/?$/);
    // Who is acting? A signed-in member (Bearer token) or a guest who only gave a name (X-Guest-Id / X-Guest-Name).
    const ideaWho = async () => {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      if (token) {
        const raw = await env.SITE_DATA.get(`membersession:${token}`);
        let userId = null;
        try { userId = raw ? JSON.parse(raw).userId : null; } catch { userId = null; }
        const user = userId ? await readUser(env, userId) : null;
        if (user) return { id: `m:${user.id}`, name: sanitizePersonName(user.name) || "Member" };
      }
      const gid = request.headers.get("X-Guest-Id") || "";
      let gname = "";
      try { gname = sanitizePersonName(decodeURIComponent(request.headers.get("X-Guest-Name") || "")); } catch { gname = ""; }
      if (/^[A-Za-z0-9_-]{16,64}$/.test(gid) && gname.length >= 2) return { id: `g:${gid}`, name: gname };
      // The site admin (the same /editor password session, not a club membership) can also vote / mark
      // availability as themselves, without joining as a guest first — many members don't have accounts
      // yet and Lujane needs to use these pages herself. Inlined (not the later isValidSession/
      // getSessionToken helpers below) because this runs earlier in the request than those are defined.
      const cookieHeader = request.headers.get("Cookie") || "";
      const sessionMatch = cookieHeader.match(/(?:^|;\s*)session=([^;]+)/);
      if (sessionMatch) {
        const raw = await env.SITE_DATA.get(`session:${sessionMatch[1]}`);
        if (raw) return { id: "admin", name: "Admin" };
      }
      return null;
    };
    const ideaClub = async (m) => { const id = decodeURIComponent(m[1]); return (await isKnownClubId(env, id)) ? id : null; };
    const refreshName = (ideas, who) => {
      for (const i of ideas) {
        if (i.by && typeof i.by === "object" && i.by.id === who.id) i.by.name = who.name;
        if (Array.isArray(i.votes)) for (const v of i.votes) if (v && typeof v === "object" && v.id === who.id) v.name = who.name;
      }
    };
    const ideaIp = request.headers.get("CF-Connecting-IP") || "unknown";
    // Only people actually IN a club (or the admin) may add options / vote on its board. Guests and
    // members of other clubs can still look at the board.
    const canActInClub = async (who, clubId) => {
      if (who.id === "admin") return true;
      if (!who.id.startsWith("m:")) return false;
      return (await readClubMemberIds(env, clubId)).includes(who.id.slice(2));
    };
    const NOT_IN_CLUB = "Only members of this club can vote or add ideas";

    // Public: current members of a club (first name + opaque id + the date they joined 4DASISTAS) — nothing else.
    const pubMembersMatch = path.match(/^\/api\/clubs\/([^/]+)\/public-members\/?$/);
    if (pubMembersMatch && request.method === "GET") {
      const cid = decodeURIComponent(pubMembersMatch[1]);
      if (!(await isKnownClubId(env, cid))) return jsonResponse({ error: "Unknown club" }, 404, corsHeaders);
      const members = [];
      for (const uid of (await readClubMemberIds(env, cid)).slice(0, 300)) {
        const u = await readUser(env, uid);
        if (!u || (u.archived && u.archived.reason !== "travelling")) continue;
        members.push({ p: await pubId(env, uid), first: pubName(u.name, u.username), joined: u.createdAt ? new Date(u.createdAt).toISOString().slice(0, 10) : "" });
      }
      members.sort((a, b) => a.first.localeCompare(b.first));
      return jsonResponse({ members }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    // Public: one person's joined date + the clubs they're in, reachable only through a club's member list or a past event's attendee list.
    if (path === "/api/public-profile" && request.method === "GET") {
      const evId = url.searchParams.get("event"), clubId = url.searchParams.get("club"), pid = String(url.searchParams.get("p") || "");
      let ids = [];
      if (evId) { const ev1 = (await readClubCal(env)).find((e) => e.id === evId); if (ev1 && !ev1.tbd && ev1.date < new Date().toISOString().slice(0, 10)) ids = (ev1.rsvps || []).filter((x) => x.status === "going" && !String(x.id).startsWith("g:")).map((x) => x.id); }
      else if (clubId) ids = await readClubMemberIds(env, clubId);
      for (const uid of ids) {
        if ((await pubId(env, uid)) !== pid) continue;
        const u = await readUser(env, uid); if (!u) break;
        const roster = await readClubRoster(env), mine = await allClubIdsContaining(env, uid);
        const todayIso = new Date().toISOString().slice(0, 10);
        const activities = (await readClubCal(env)).filter((e) => !e.tbd && e.date < todayIso && (e.rsvps || []).some((x) => x.id === uid && x.status === "going"))
          .sort((a, b) => b.date.localeCompare(a.date)).map((e) => ({ title: e.title, date: e.date, clubs: calClubs(e).map((cid) => (roster.find((c) => c.id === cid) || {}).title).filter(Boolean) }));
        return jsonResponse({ first: pubName(u.name, u.username), joined: u.createdAt ? new Date(u.createdAt).toISOString().slice(0, 10) : "", clubs: mine.map((id) => (roster.find((c) => c.id === id) || {}).title).filter(Boolean), activities }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
      }
      return jsonResponse({ error: "Not found" }, 404, corsHeaders);
    }
    // ---- Find yourself (sign in from an event form): GET /api/member-search?q=ana  →  [{username, name:"Ana K."}] ----
    if (path === "/api/member-search" && request.method === "GET") {
      const q = String(url.searchParams.get("q") || "").trim().toLowerCase();
      if (q.length < 3) return jsonResponse({ results: [] }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
      const rk = `msrch:${request.headers.get("CF-Connecting-IP") || "unknown"}:${Math.floor(Date.now() / 3600000)}`;
      const used = Number(await env.SITE_DATA.get(rk) || 0);
      if (used >= 60) return jsonResponse({ error: "Too many searches — try again in a while" }, 429, corsHeaders);
      await env.SITE_DATA.put(rk, String(used + 1), { expirationTtl: 3700 });
      if (!_memberSearchCache || Date.now() - _memberSearchCache.at > 120000) _memberSearchCache = { at: Date.now(), people: (await listAllUsers(env)).filter((u) => u && u.username && u.name && !(u.archived && u.archived.reason !== "travelling")).map((u) => ({ username: u.username, name: String(u.name), low: String(u.name).toLowerCase() })) };
      const short = (n) => { const parts = n.split(/\s+/); return parts.length > 1 ? `${parts[0]} ${parts[parts.length - 1].slice(0, 1).toUpperCase()}.` : parts[0]; };
      return jsonResponse({ results: _memberSearchCache.people.filter((p) => p.low.includes(q)).slice(0, 6).map((p) => ({ username: p.username, name: short(p.name) })) }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    // ---- Club calendar (public list; member details + RSVP) ----
    // ---- Event photos (uploaded by an admin or a page editor): stored in D1, served with long caching ----
    const imgMatch = path.match(/^\/api\/cal-img\/([a-z0-9]{8,24})$/);
    if (imgMatch && request.method === "GET") {
      const ck = new Request(`${url.origin}/api/cal-img/${imgMatch[1]}`), hit = await caches.default.match(ck);
      if (hit) return hit;
      await calImgEnsure(env);
      const f = await env.DB.prepare("SELECT ctype, b64 FROM cal_images WHERE id = ?").bind(imgMatch[1]).first();
      if (!f) return new Response("Not found", { status: 404, headers: corsHeaders });
      const res = new Response(Uint8Array.from(atob(f.b64), (c) => c.charCodeAt(0)), { status: 200, headers: { ...corsHeaders, "Content-Type": f.ctype || "image/jpeg", "Cache-Control": "public, max-age=31536000, immutable" } });
      ctx.waitUntil(caches.default.put(ck, res.clone()));
      return res;
    }
    // ---- "Anyone with this link can edit the page": a secret link per event (made/turned off by an admin). Editors change the page's CONTENT only: not who's signed up, the club, the spots or the payment details. ----
    const editMatch = path.match(/^\/api\/event-edit\/([a-f0-9]{24})(\/image)?\/?$/);
    if (editMatch) {
      const tok = editMatch[1], all0 = await readClubCal(env), ev0 = all0.find((e) => e.editToken === tok);
      if (!ev0) return jsonResponse({ error: "This edit link isn't active any more — ask the organiser for a new one" }, 404, corsHeaders);
      const view = (e) => ({ id: e.id, slug: e.slug || "", title: e.title, date: e.date, time: e.time || "", place: e.place || "", mapUrl: e.mapUrl || "", desc: e.desc || "", rsvpBy: e.rsvpBy || "", tbd: !!e.tbd, blocks: e.blocks || [], theme: e.theme || null, hosts: e.hosts || [], clubIds: calClubs(e), form: e.form ? { title: e.form.title, intro: e.form.intro || "", footer: e.form.footer || "", fields: e.form.fields } : null, hasPayment: !!(e.form && e.form.payment), clubTitle: calClubs(e).map((c) => (roster0.find((r) => r.id === c) || {}).title || "").filter(Boolean).join(" × ") });
      const roster0 = await readClubRoster(env);
      if (editMatch[2] === "/image" && request.method === "POST") { const r = await calImgSave(request, env, ev0.id); return r.error ? jsonResponse({ error: r.error }, 400, corsHeaders) : jsonResponse(r, 201, corsHeaders); }
      if (!editMatch[2] && request.method === "GET") return jsonResponse({ event: view(ev0) }, 200, corsHeaders);
      if (!editMatch[2] && request.method === "PUT") {
        let body = {}; try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
        if (String(body.mapUrl || "").trim() && !isGoogleMapsUrl(body.mapUrl)) return jsonResponse({ error: "That isn't a Google Maps link — in Google Maps tap Share → Copy link" }, 400, corsHeaders);
        const f = calFields({ ...ev0, title: body.title !== undefined ? body.title : ev0.title, date: body.date !== undefined ? body.date : ev0.date, time: body.time !== undefined ? body.time : ev0.time, place: body.place !== undefined ? body.place : ev0.place, mapUrl: body.mapUrl !== undefined ? body.mapUrl : ev0.mapUrl, desc: body.desc !== undefined ? body.desc : ev0.desc, rsvpBy: body.rsvpBy !== undefined ? body.rsvpBy : ev0.rsvpBy, capacity: calCap(ev0) });
        if (f.title.length < 3) return jsonResponse({ error: "Give the event a name (3+ letters)" }, 400, corsHeaders);
        if (!ev0.tbd && !isValidDateString(f.date)) return jsonResponse({ error: "Pick a date" }, 400, corsHeaders);
        if (ev0.tbd) { f.date = ""; f.rsvpBy = ""; }
        const design = calDesignFields(body);
        let cf = null; const formGiven = body.form !== undefined;
        if (formGiven && body.form) { cf = sanitizeCalForm(body.form); if (cf) { delete cf.rsvpBy; delete cf.desc; if (ev0.form && ev0.form.payment) cf.payment = ev0.form.payment; else delete cf.payment; } } // editors never touch the payment details
        const newSlug = f.title !== ev0.title ? calMakeSlug(all0, { ...ev0, title: f.title, slug: "" }) : "";
        const hk = `calhist:${ev0.id}`; let hist = []; try { hist = JSON.parse((await env.SITE_DATA.get(hk)) || "[]"); } catch {}
        hist = [calEditSnap(ev0), ...hist].slice(0, 5); // the last 5 versions are kept so an admin can undo
        const out = await calMutate(env, ev0.id, (ev) => {
          Object.assign(ev, f); ev.histN = hist.length;
          if (newSlug && newSlug !== ev.slug) { ev.oldSlugs = [...new Set([...(ev.oldSlugs || []), ev.slug].filter(Boolean))].slice(-5); ev.slug = newSlug; }
          calApplyDesign(ev, design);
          if (formGiven && cf) ev.form = cf;
          ev.editedAt = Date.now(); ev.editedVia = "link";
        });
        if (!out) return jsonResponse({ error: "Busy right now — try again in a moment" }, 503, corsHeaders);
        try { await env.SITE_DATA.put(hk, JSON.stringify(hist)); } catch {}
        return jsonResponse({ ok: true, event: view(out) }, 200, corsHeaders);
      }
      return jsonResponse({ error: "Not allowed" }, 405, corsHeaders);
    }

    const calMatch = path.match(/^\/api\/club-calendar(?:\/([^/]+)(\/rsvp|\/form|\/attendees|\/interest|\/paid)?)?\/?$/);
    if (calMatch) {
      const M = request.method;
      const roster = await readClubRoster(env);
      const clubTitle = (id) => (roster.find((c) => c.id === id) || {}).title || "";
      if (!calMatch[1] && M === "GET") {
        const calAll = await readClubCal(env); if (calEnsureSlugs(calAll)) ctx.waitUntil(calBackfillSlugs(env));
        const events = calAll.filter((e) => !e.tbd).sort((a, b) => a.date.localeCompare(b.date) || String(a.time).localeCompare(String(b.time)))
          .map((e) => ({ id: e.id, slug: e.slug, clubId: e.clubId, clubIds: calClubs(e), clubTitle: calClubs(e).map(clubTitle).filter(Boolean).join(" × "), title: e.title, date: e.date, time: e.time || "", hasForm: !!e.form, publicForm: !!e.form }));
        // Idea bubbles that the admin gave a DATE also show on the calendars (cached ~2 minutes so this stays cheap).
        if (!_calIdeaCache || Date.now() - _calIdeaCache.at > 120000) {
          const items = [];
          for (const c of roster) for (const i of await readClubIdeas(env, c.id)) if (i && /^\d{4}-\d{2}-\d{2}$/.test(i.date || "")) items.push({ id: `idea:${c.id}:${i.id}`, kind: "idea", clubId: c.id, clubIds: [c.id], clubTitle: c.title || "", title: i.title, emoji: i.emoji || "", date: i.date, time: "", done: !!i.done });
          _calIdeaCache = { at: Date.now(), items };
        }
        // every dated event/idea, past ones too — the public calendar goes back to the very first event. An idea that already became a real event that day is shown once (as the event).
        const ideaItems = _calIdeaCache.items.filter((i) => !events.some((e) => e.date === i.date && e.clubIds.some((c) => (i.clubIds || [i.clubId]).includes(c)) && sameActivity(e.title, i.title)));
        return jsonResponse({ events: events.concat(ideaItems).sort((a, b) => a.date.localeCompare(b.date)) }, 200, corsHeaders);
      }
      // PUBLIC (privacy-minimal): who attended a PAST event — first names only; people with a profile get an opaque id so their joined date + clubs can be looked up.
      if (calMatch[1] && calMatch[2] === "/attendees" && M === "GET") {
        const ev0 = calFind(await readClubCal(env), calMatch[1]);
        if (!ev0) return jsonResponse({ error: "Event not found" }, 404, corsHeaders);
        if (ev0.tbd || ev0.date >= new Date().toISOString().slice(0, 10)) return jsonResponse({ past: false, attendees: [] }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
        const out = [];
        for (const r of (ev0.rsvps || []).filter((x) => x.status === "going")) {
          if (String(r.id).startsWith("g:")) { out.push({ first: pubName(r.name) }); continue; } // no profile: a first name only
          const u = await readUser(env, r.id);
          out.push({ first: pubName(u ? u.name : r.name, u && u.username), p: await pubId(env, r.id) }); // members are listed by USERNAME
        }
        out.sort((a, b) => a.first.localeCompare(b.first));
        return jsonResponse({ past: true, attendees: out }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
      }
      // MEMBERS ONLY: the "to be scheduled" events of the clubs this member is in (no date yet — they show interest instead of RSVPing).
      if (calMatch[1] === "tbd" && !calMatch[2] && M === "GET") {
        const who = await ideaWho();
        if (!who || !who.id.startsWith("m:")) return jsonResponse({ events: [] }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
        const uid = who.id.slice(2), mineClubs = [];
        for (const c of roster) if ((await readClubMemberIds(env, c.id)).includes(uid)) mineClubs.push(c.id);
        const events = (await readClubCal(env)).filter((e) => e.tbd && calClubs(e).some((c) => mineClubs.includes(c)))
          .map((e) => ({ id: e.id, clubTitle: calClubs(e).map(clubTitle).filter(Boolean).join(" × "), title: e.title, time: e.time || "", place: e.place || "", desc: e.desc || "", interested: (e.interest || []).length, mine: (e.interest || []).some((i) => i.id === uid) }));
        return jsonResponse({ events }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
      }
      if (calMatch[1]) {
        const who = await ideaWho();
        const all = await readClubCal(env); if (calEnsureSlugs(all)) ctx.waitUntil(calBackfillSlugs(env));
        const ev = calFind(all, calMatch[1]);
        if (!ev) return jsonResponse({ error: "Event not found" }, 404, corsHeaders);
        if (!who || !(who.id.startsWith("m:") || who.id === "admin")) {
          // A PUBLICIZED event (publicForm): anyone can open its form straight away and submit it with just a name — no account needed.
          if (ev.form) { // ANY event with a form can be filled in without an account
            if (!calMatch[2] && M === "GET") return jsonResponse({ id: ev.id, slug: ev.slug, clubTitle: calClubs(ev).map(clubTitle).filter(Boolean).join(" × "), title: ev.title, date: ev.date, time: ev.time || "", place: ev.place || "", mapUrl: ev.mapUrl || "", desc: ev.desc || "", blocks: ev.blocks || [], theme: ev.theme || null, hosts: ev.hosts || [], clubIds: calClubs(ev), publicForm: true, form: ev.form, guest: true, ...calCapInfo(ev), rsvpBy: ev.rsvpBy || "", closed: !!(ev.rsvpBy && new Date().toISOString().slice(0, 10) > ev.rsvpBy) }, 200, corsHeaders);
            if (calMatch[2] === "/form" && M === "POST") {
              if (!ideaRateOk(ideaIp)) return jsonResponse({ error: "Slow down a little — try again in a minute" }, 429, corsHeaders);
              let fb; try { fb = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
              if (ev.rsvpBy && new Date().toISOString().slice(0, 10) > ev.rsvpBy) return jsonResponse({ error: "Sign-ups for this event are closed" }, 400, corsHeaders);
              if (ev.date < new Date().toISOString().slice(0, 10)) return jsonResponse({ error: "This event has already happened" }, 400, corsHeaders);
              if (fb && fb.pin !== undefined) {
                // Base member details came with the form: create the account (and sign them in), then record the sign-up as theirs.
                const chk0 = checkCalAnswers(ev.form, fb.answers);
                if (chk0.error) return jsonResponse({ error: chk0.error }, 400, corsHeaders);
                const made = await createMemberFromForm(env, ctx, ideaIp, fb);
                if (made.error) return jsonResponse({ error: made.error }, made.status, corsHeaders);
                { const sel = calAddonSelection(ev.form, fb.addons); await calFormPut(env, ev.id, made.user.id, { name: made.user.name, answers: chk0.answers, at: Date.now(), ...(sel.ids.length ? { addons: sel.ids } : {}), ...(sel.total != null ? { total: sel.total } : {}) }); }
                const st0 = await calSpotStatus(env, ev, made.user.id);
                { const c0 = await calAddRsvp(env, ev.id, { id: made.user.id, name: made.user.name, status: st0, at: Date.now(), viaForm: true }); if (c0) ev.rsvps = c0.rsvps; }
                notifyAdminOfFormSignup(env, ctx, ev, { name: made.user.name, phone: made.user.phone, newAccount: true }, chk0.answers, calAddonSelection(ev.form, fb.addons));
                return jsonResponse({ ok: true, created: true, eventStatus: st0, token: made.token, ...publicUser(made.user), clubs: [], waitlist: [] }, 201, corsHeaders);
              }
              const nm = sanitizePersonName(fb && fb.name);
              if (nm.length < 2) return jsonResponse({ error: "Please type your name" }, 400, corsHeaders);
              const contact = String((fb && fb.contact) || "").replace(/[\x00-\x1f\x7f<>]/g, " ").trim().slice(0, 80);
              const chk = checkCalAnswers(ev.form, fb && fb.answers);
              if (chk.error) return jsonResponse({ error: chk.error }, 400, corsHeaders);
              let map = {}; try { map = JSON.parse((await env.SITE_DATA.get(calFormKey(ev.id))) || "{}") || {}; } catch {}
              if (Object.keys(map).length >= 1500) return jsonResponse({ error: "This form is full" }, 400, corsHeaders);
              const gid = `g:${crypto.randomUUID().slice(0, 10)}`;
              { const sel = calAddonSelection(ev.form, fb && fb.addons); await calFormPut(env, ev.id, gid, { name: nm, contact, answers: chk.answers, at: Date.now(), guest: true, ...(sel.ids.length ? { addons: sel.ids } : {}), ...(sel.total != null ? { total: sel.total } : {}) }); }
              const stG = await calSpotStatus(env, ev, gid);
              await calAddRsvp(env, ev.id, { id: gid, name: nm, status: stG, at: Date.now(), guest: true, viaForm: true }); // shows in the attendee list too
              notifyAdminOfFormSignup(env, ctx, ev, { name: nm, contact }, chk.answers, calAddonSelection(ev.form, fb && fb.addons));
              return jsonResponse({ ok: true, eventStatus: stG }, 200, corsHeaders);
            }
          }
          return jsonResponse({ error: "Log in or sign up to see event details and RSVP" }, 401, corsHeaders);
        }
        const uid = who.id.startsWith("m:") ? who.id.slice(2) : "";
        let inClub = false;
        if (uid) for (const cid of calClubs(ev)) if ((await readClubMemberIds(env, cid)).includes(uid)) { inClub = true; break; }
        const mine = (ev.rsvps || []).find((r) => r.id === uid);
        if (!calMatch[2] && M === "GET") {
          return jsonResponse({ id: ev.id, slug: ev.slug, clubId: ev.clubId, clubIds: calClubs(ev), clubTitle: calClubs(ev).map(clubTitle).filter(Boolean).join(" × "), title: ev.title, date: ev.date, time: ev.time || "", place: ev.place || "", mapUrl: ev.mapUrl || "", desc: ev.desc || "", blocks: ev.blocks || [], theme: ev.theme || null, hosts: ev.hosts || [], rsvpBy: ev.rsvpBy || "", closed: !!(ev.rsvpBy && new Date().toISOString().slice(0, 10) > ev.rsvpBy),
            going: (ev.rsvps || []).filter((r) => r.status === "going").length, mine: mine ? mine.status : null, inClub,
            publicForm: !!ev.form, form: ev.form || null, ...calCapInfo(ev), waitPos: mine && mine.status === "waitlist" ? calWaitPos(ev, uid) : 0, claimedPaid: !!(mine && mine.claimedPaid), paid: !!(mine && mine.paid), myAddons: ev.form && uid ? ((JSON.parse((await env.SITE_DATA.get(calFormKey(ev.id))) || "{}")[uid] || {}).addons || []) : [], myAnswers: ev.form && uid ? ((JSON.parse((await env.SITE_DATA.get(calFormKey(ev.id))) || "{}")[uid] || {}).answers || null) : null }, 200, corsHeaders);
        }
        if (calMatch[2] === "/form" && M === "POST") {
          if (!uid) return jsonResponse({ error: "Sign in as a member to fill the form" }, 403, corsHeaders);
          if (!ev.form) return jsonResponse({ error: "This event has no form" }, 404, corsHeaders);
          if (!ideaRateOk(ideaIp)) return jsonResponse({ error: "Slow down a little — try again in a minute" }, 429, corsHeaders);
          let fb; try { fb = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
          const chk = checkCalAnswers(ev.form, fb && fb.answers);
          if (chk.error) return jsonResponse({ error: chk.error }, 400, corsHeaders);
          let map = {}; try { map = JSON.parse((await env.SITE_DATA.get(calFormKey(ev.id))) || "{}") || {}; } catch {}
          const wasIn = (ev.rsvps || []).find((r) => r.id === uid);
          if (!wasIn && ev.rsvpBy && new Date().toISOString().slice(0, 10) > ev.rsvpBy) return jsonResponse({ error: "Sign-ups for this event are closed" }, 400, corsHeaders);
          if (!wasIn && ev.date < new Date().toISOString().slice(0, 10)) return jsonResponse({ error: "This event has already happened" }, 400, corsHeaders);
          { const sel = calAddonSelection(ev.form, fb && fb.addons); map = await calFormPut(env, ev.id, uid, { name: who.name, answers: chk.answers, at: Date.now(), ...(sel.ids.length ? { addons: sel.ids } : {}), ...(sel.total != null ? { total: sel.total } : {}) }); }
          // Submitting the form IS the RSVP: club members are going at once, people from other clubs wait for approval.
          let status = wasIn ? wasIn.status : null;
          if (!wasIn) {
            status = await calSpotStatus(env, ev, uid); // a form sign-up is open to everyone: filling it in IS the RSVP (past the limit = waitlist)
            { const c1 = await calAddRsvp(env, ev.id, { id: uid, name: who.name, status, at: Date.now(), viaForm: true }); if (c1) ev.rsvps = c1.rsvps; }
            notifyAdminOfFormSignup(env, ctx, ev, { name: who.name, newAccount: false }, chk.answers, calAddonSelection(ev.form, fb && fb.addons));
          }
          return jsonResponse({ ok: true, answers: chk.answers, addons: (map[uid] || {}).addons || [], total: (map[uid] || {}).total ?? null, mine: status, waitPos: status === "waitlist" ? calWaitPos(ev, uid) : 0, going: (ev.rsvps || []).filter((r) => r.status === "going").length }, 200, corsHeaders);
        }
        if (calMatch[2] === "/paid" && M === "POST") { // "I've sent my payment": a flag the organiser sees next to the person's name until they confirm it
          if (!uid || !mine) return jsonResponse({ error: "Sign up for the event first" }, 403, corsHeaders);
          await calMutate(env, ev.id, (e) => { const r = (e.rsvps || []).find((x) => x.id === uid); if (r && !r.paid) r.claimedPaid = Date.now(); });
          return jsonResponse({ ok: true }, 200, corsHeaders);
        }
        if (calMatch[2] === "/interest" && (M === "POST" || M === "DELETE")) {
          if (!uid || !ev.tbd) return jsonResponse({ error: "Sign in as a member to show interest" }, 403, corsHeaders);
          if (!inClub) return jsonResponse({ error: "This one is for members of the club" }, 403, corsHeaders);
          ev.interest = (ev.interest || []).filter((i) => i.id !== uid);
          if (M === "POST") {
            // They must have filled in their availability for the current period first — it's what we use to pick the date.
            const per = await readAvailPeriodKV(env), doc = parseIdeaAvailDoc(await readIaDoc(env, `m:${uid}`));
            const inPer = (d) => d >= per.start && d <= per.end;
            if (!Object.keys(doc.days).some(inPer) && !Object.keys(doc.no).some(inPer)) return jsonResponse({ error: "Please add your availability first, then show interest", needAvail: true }, 400, corsHeaders);
            ev.interest.push({ id: uid, name: who.name, at: Date.now() });
          }
          await writeClubCal(env, all);
          return jsonResponse({ ok: true, mine: M === "POST", interested: ev.interest.length }, 200, corsHeaders);
        }
        if (calMatch[2] === "/rsvp" && (M === "POST" || M === "DELETE")) {
          if (!uid) return jsonResponse({ error: "Sign in as a member to RSVP" }, 403, corsHeaders);
          if (!ideaRateOk(ideaIp)) return jsonResponse({ error: "Slow down a little — try again in a minute" }, 429, corsHeaders);
          if (M === "POST" && ev.rsvpBy && new Date().toISOString().slice(0, 10) > ev.rsvpBy) return jsonResponse({ error: "RSVPs for this event are closed" }, 400, corsHeaders);
          if (M === "POST" && ev.date < new Date().toISOString().slice(0, 10)) return jsonResponse({ error: "This event has already happened" }, 400, corsHeaders);
          let status = null;
          if (M === "DELETE") { const c2 = await calDropRsvp(env, ev.id, uid); ev.rsvps = c2 ? c2.rsvps : (ev.rsvps || []).filter((r) => r.id !== uid); ctx.waitUntil(calAfterRemoval(env, ctx, ev.id, uid)); }
          else {
            status = inClub ? await calSpotStatus(env, ev, uid) : "pending";
            const c3 = await calAddRsvp(env, ev.id, { id: uid, name: who.name, status, at: Date.now() }); ev.rsvps = c3 ? c3.rsvps : (ev.rsvps || []).filter((r) => r.id !== uid).concat([{ id: uid, name: who.name, status, at: Date.now() }]);
          }
          if (status === "pending" && !mine) {
            const origin = env.SITE_ORIGIN || "https://4dasistas.ca";
            const html = emailShell(env, { emoji: "🎟️", title: "RSVP request", preheader: `${who.name} → ${ev.title}`,
              body: `<p style="margin:0 0 6px"><strong>${escapeHtml(who.name)}</strong> (not in ${escapeHtml(calClubs(ev).map(clubTitle).join(" × "))}) asked to RSVP to</p><p style="margin:0 0 14px"><strong>${escapeHtml(ev.title)}</strong> · ${escapeHtml(ev.date)}</p>${emailBtn(`${origin}/#/clubs/calendar`, "Review the request →")}`,
              footer: "Accept or decline from the event's attendee list on the Club calendar." });
            sendAdminEmail(env, ctx, `RSVP request: ${who.name} → ${ev.title}`, html);
          }
          return jsonResponse({ ok: true, mine: status, waitPos: status === "waitlist" ? calWaitPos(ev, uid) : 0, going: ev.rsvps.filter((r) => r.status === "going").length }, 200, corsHeaders);
        }
      }
    }

    if (ideasListMatch && request.method === "GET") {
      const clubId = await ideaClub(ideasListMatch);
      if (!clubId) return jsonResponse({ error: "Unknown club" }, 404, corsHeaders);
      return jsonResponse({ ideas: sortedPublicIdeas(await readClubIdeas(env, clubId), await ideaWho()) }, 200, corsHeaders);
    }
    if (ideasListMatch && request.method === "POST") {
      const clubId = await ideaClub(ideasListMatch);
      if (!clubId) return jsonResponse({ error: "Unknown club" }, 404, corsHeaders);
      const who = await ideaWho();
      if (!who) return jsonResponse({ error: "Enter your name first" }, 401, corsHeaders);
      if (!(await canActInClub(who, clubId))) return jsonResponse({ error: NOT_IN_CLUB }, 403, corsHeaders);
      if (!ideaRateOk(ideaIp)) return jsonResponse({ error: "Slow down a little — try again in a minute" }, 429, corsHeaders);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const title = String(body.title || "").replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim();
      if (title.length < 3 || title.length > 80) return jsonResponse({ error: "The title needs 3–80 characters" }, 400, corsHeaders);
      // The map link is optional; if one is given it must be a real Google Maps link.
      const mapUrl = String(body.mapUrl || "").trim() === "" ? "" : isGoogleMapsUrl(body.mapUrl);
      if (mapUrl === null || mapUrl === undefined || (mapUrl === "" && String(body.mapUrl || "").trim() !== "")) return jsonResponse({ error: "That doesn't look like a Google Maps link. In Google Maps tap Share → Copy link, then paste it here." }, 400, corsHeaders);
      const cuisine = sanitizeCuisine(body.cuisine);
      if (clubId === CUISINE_CLUB_ID && cuisine.length < 2) return jsonResponse({ error: "Please add the cuisine type (e.g. Lebanese, Korean, Dessert)" }, 400, corsHeaders);
      const price = sanitizePrice(body.price);
      const ideas = await readClubIdeas(env, clubId);
      if (ideas.length >= IDEAS_MAX_PER_CLUB) return jsonResponse({ error: "This board is full — vote on an existing option instead" }, 400, corsHeaders);
      if (ideas.filter((i) => ideaPeople(i).by.id === who.id).length >= IDEAS_MAX_PER_PERSON) return jsonResponse({ error: `You already added ${IDEAS_MAX_PER_PERSON} options here — remove one to add another` }, 400, corsHeaders);
      if (ideas.some((i) => i.title.toLowerCase() === title.toLowerCase())) return jsonResponse({ error: "Someone already suggested that — go vote for it!" }, 409, corsHeaders);
      refreshName(ideas, who);
      const clubEmoji = ((await readClubRoster(env)).find((c) => c.id === clubId) || {}).emoji || "";
      ideas.push({ id: crypto.randomUUID(), title, mapUrl, date: "", emoji: sanitizeIdeaEmoji(body.emoji) || pickIdeaEmoji(title, cuisine, clubEmoji), ...(cuisine ? { cuisine } : {}), ...(price ? { price } : {}), by: who, at: Date.now(), votes: [who], adjust: 0 });
      await writeClubIdeas(env, clubId, ideas);
      return jsonResponse({ ideas: sortedPublicIdeas(ideas, who) }, 201, corsHeaders);
    }
    if (ideaVoteMatch && request.method === "POST") {
      const clubId = await ideaClub(ideaVoteMatch);
      if (!clubId) return jsonResponse({ error: "Unknown club" }, 404, corsHeaders);
      const who = await ideaWho();
      if (!who) return jsonResponse({ error: "Enter your name first" }, 401, corsHeaders);
      if (!(await canActInClub(who, clubId))) return jsonResponse({ error: NOT_IN_CLUB }, 403, corsHeaders);
      if (!ideaRateOk(ideaIp)) return jsonResponse({ error: "Slow down a little — try again in a minute" }, 429, corsHeaders);
      const ideaId = decodeURIComponent(ideaVoteMatch[2]);
      const ideas = await readClubIdeas(env, clubId);
      const idea = ideas.find((i) => i.id === ideaId);
      if (!idea) return jsonResponse({ error: "That option was removed" }, 404, corsHeaders);
      if (idea.done) return jsonResponse({ error: "We've already done this one — voting is closed." }, 409, corsHeaders);
      refreshName(ideas, who);
      const voters = ideaPeople(idea).voters;
      idea.votes = voters.some((v) => v.id === who.id) ? voters.filter((v) => v.id !== who.id) : [...voters, who];
      await writeClubIdeas(env, clubId, ideas);
      return jsonResponse({ ideas: sortedPublicIdeas(ideas, who) }, 200, corsHeaders);
    }
    if (ideaOneMatch && request.method === "DELETE") {
      const clubId = await ideaClub(ideaOneMatch);
      if (!clubId) return jsonResponse({ error: "Unknown club" }, 404, corsHeaders);
      const who = await ideaWho();
      if (!who) return jsonResponse({ error: "Enter your name first" }, 401, corsHeaders);
      const ideaId = decodeURIComponent(ideaOneMatch[2]);
      const ideas = await readClubIdeas(env, clubId);
      const idea = ideas.find((i) => i.id === ideaId);
      if (!idea) return jsonResponse({ error: "That option was already removed" }, 404, corsHeaders);
      if (ideaPeople(idea).by.id !== who.id) return jsonResponse({ error: "You can only remove options you added" }, 403, corsHeaders);
      const rest = ideas.filter((i) => i.id !== ideaId);
      await writeClubIdeas(env, clubId, rest);
      return jsonResponse({ ideas: sortedPublicIdeas(rest, who) }, 200, corsHeaders);
    }

    // Availability is one general schedule per person, shared across every club (not a separate
    // one per club) - these two routes are intentionally NOT nested under /api/clubs/:clubId/.
    const ideaAvailAllMatch = path.match(/^\/api\/idea-availability\/all\/?$/);
    if (ideaAvailAllMatch && request.method === "GET") {
      const who = await ideaWho();
      if (!who) return jsonResponse({ error: "Enter your name first" }, 401, corsHeaders);
      let people = await readIdeaAvailPeople(env);
      let waitingIds = []; // people in the viewer's scope who haven't submitted their availability yet
      // A signed-in member only sees (and is only counted with) people from the clubs they're really in;
      // the admin sees everyone. Name-only guests get no names at all (handled below).
      if (who.id.startsWith("m:")) {
        const myId = who.id.slice(2);
        const mine = new Set();
        const peerClubs = {};
        for (const clubId of await clubIdList(env)) {
          if (COMMUNITY_CLUBS.has(clubId)) continue; // not a vote / availability club
          const ids = await readClubMemberIds(env, clubId);
          if (ids.includes(myId)) mine.add(clubId);
          for (const uid of ids) (peerClubs[uid] = peerClubs[uid] || new Set()).add(clubId);
        }
        people = people.filter((p) => p.id === who.id || (p.id.startsWith("m:") && [...(peerClubs[p.id.slice(2)] || [])].some((c) => mine.has(c))));
        // Optional narrowing to ONE of the viewer's clubs (members of several clubs choose which crowd to look at).
        const only = url.searchParams.get("club");
        if (only && mine.has(only)) people = people.filter((p) => p.id.startsWith("m:") && (peerClubs[p.id.slice(2)] || new Set()).has(only));
        const scopeOnly = only && mine.has(only) ? only : null;
        waitingIds = Object.keys(peerClubs).filter((uid) => uid !== myId && [...peerClubs[uid]].some((c) => (scopeOnly ? c === scopeOnly : mine.has(c))));
      } else if (who.id === "admin" && url.searchParams.get("club")) {
        const ids = new Set(await readClubMemberIds(env, url.searchParams.get("club")));
        people = people.filter((p) => p.id.startsWith("m:") && ids.has(p.id.slice(2)));
        waitingIds = [...ids];
      }
      // counts = people AVAILABLE per slot (green + unset; red excluded), preferred = green only, unavailable = red.
      // Unset slots only count inside the availability PERIOD (set by the main admin).
      const counts = {}, preferred = {}, unavailable = {};
      // Members can look back at any SAVED period (?start=&end=); otherwise it is the current one.
      let viewPeriod = await readAvailPeriodKV(env), viewPast = false;
      const qs = url.searchParams.get("start"), qe = url.searchParams.get("end");
      if (qs && qe && /^\d{4}-\d{2}-\d{2}$/.test(qs) && /^\d{4}-\d{2}-\d{2}$/.test(qe) && (await listAvailPeriods(env)).periods.some((h) => h.start === qs && h.end === qe)) { viewPeriod = { start: qs, end: qe }; viewPast = true; }
      const windowDates = availPeriodDates(viewPeriod, viewPast); // the fixed period the main admin opened (nothing outside it is assumed free)
      const bump = (map, date, part) => { const slot = (map[date] = map[date] || { morning: 0, afternoon: 0, evening: 0 }); slot[part]++; };
      // Only people who actually answered something in THIS period count as having voted — an old answer from an earlier period doesn't (that is why "4 of 15 haven't voted" was wrong).
      people = people.filter((p) => windowDates.some((d) => (p.days[d] || []).length || (p.no[d] || []).length));
      for (const p of people) {
        const dates = new Set([...windowDates, ...Object.keys(p.days), ...Object.keys(p.no)]);
        for (const date of dates) {
          for (const part of allowedAvailParts(date)) {
            const yes = (p.days[date] || []).includes(part), red = (p.no[date] || []).includes(part);
            if (red) { bump(unavailable, date, part); continue; }
            if (yes) bump(preferred, date, part);
            if (yes || windowDates.includes(date)) bump(counts, date, part);
          }
        }
      }
      const respondents = people.length;
      const responded = new Set(people.map((p) => p.id));
      const todayIso = new Date().toISOString().slice(0, 10);
      const waiting = [];
      for (const uid of waitingIds) {
        if (responded.has(`m:${uid}`)) continue;
        const u = await readUser(env, uid);
        if (!u) continue;
        if (u.archived && !(u.archived.reason === "travelling" && u.archived.until && u.archived.until < todayIso)) continue; // archived people aren't expected to vote
        waiting.push(sanitizePersonName(u.name) || "Someone");
      }
      waiting.sort((a, b) => a.localeCompare(b));
      // Signed-in members (and the site admin) see who's free by name when they tap a square; a
      // name-only guest still only sees the anonymous counts/colour intensity.
      const showNames = !who.id.startsWith("g:");
      return jsonResponse({ counts, preferred, unavailable, windowDates, respondents, ...(showNames ? { people, waiting } : {}) }, 200, corsHeaders);
    }

    const ideaAvailMatch = path.match(/^\/api\/idea-availability\/?$/);
    if (ideaAvailMatch && (request.method === "GET" || request.method === "PUT")) {
      const who = await ideaWho();
      if (!who) return jsonResponse({ error: "Enter your name first" }, 401, corsHeaders);
      if (request.method === "GET") {
        const { days, no, submitted } = parseIdeaAvailDoc(await readIaDoc(env, who.id));
        return jsonResponse({ days, no, submitted }, 200, corsHeaders);
      }
      if (!ideaRateOk(ideaIp)) return jsonResponse({ error: "Slow down a little — try again in a minute" }, 429, corsHeaders);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const { days, no } = sanitizeIdeaAvail(body);
      await writeIaDoc(env, who.id, JSON.stringify({ name: who.name, days, no }));
      _ideaAvailMemo = { at: 0, people: null }; // the next read in this instance is fresh
      return jsonResponse({ days, no, submitted: true }, 200, corsHeaders);
    }

    // ---- Signed-in members can browse every profile (names + clubs; never usernames or PINs) ----
    const memberIdFromRequest = async () => {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      if (!token) return null;
      const raw = await env.SITE_DATA.get(`membersession:${token}`);
      if (!raw) return null;
      try { return JSON.parse(raw).userId || null; } catch { return null; }
    };
    // Signed-in people (members, admin, club admins) have no hourly submission limit.
    const isSignedInAnyone = async () => {
      if (await memberIdFromRequest()) return true;
      const ck = request.headers.get("Cookie") || "";
      for (const [name, prefix] of [["session", "session:"], ["leadsession", "leadsession:"]]) {
        const m = ck.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
        if (m && (await env.SITE_DATA.get(prefix + m[1]))) return true;
      }
      return false;
    };
    // ---- Public: anyone can suggest an event (link, name, date, city). Stored for the admin + emailed. ----
    // The "Submit an event" form can have extra questions + an intro, edited by the main admin (Admin → The Calendar → Event submission form).
    const readEventFormCfg = async () => { try { const c = JSON.parse((await env.SITE_DATA.get("evsubform")) || "{}") || {}; return { intro: String(c.intro || ""), form: c.form && c.form.fields ? c.form : null }; } catch { return { intro: "", form: null }; } };
    if (path === "/api/event-form-config" && request.method === "GET") return jsonResponse(await readEventFormCfg(), 200, { ...corsHeaders, "Cache-Control": "no-store" });
    // SECURITY: the admin routes between here and the main admin guard further down run BEFORE that guard, so they check the main-admin session themselves.
    if ((path === "/api/admin/event-form-config" || path === "/api/admin/needs" || path === "/api/admin/steps" || path === "/api/admin/step-rounds" || path === "/api/admin/stay-status" || path.startsWith("/api/admin/step-pledges") || path.startsWith("/api/admin/step-participants") || path.startsWith("/api/admin/badminton/")) && !(await isAdminRequest(env, request))) return jsonResponse({ error: "Unauthorized" }, 401, corsHeaders);
    if (path === "/api/admin/event-form-config" && request.method === "PUT") {
      let body; try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const cfg = { intro: String(body.intro || "").replace(/[\x00-\x08\x0b-\x1f\x7f]/g, " ").trim().slice(0, 500), form: sanitizeCalForm(body.form) };
      await env.SITE_DATA.put("evsubform", JSON.stringify(cfg));
      return jsonResponse({ ok: true, ...cfg }, 200, corsHeaders);
    }
    if (path === "/api/event-suggestions" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (body.website) return jsonResponse({ ok: true }, 200, corsHeaders); // honeypot: bots fill hidden fields
      const clean = (v, max) => String(v || "").replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
      const virtual = body.virtual === true;
      const name = clean(body.name, 120), city = virtual ? "Virtual" : clean(body.city, 60), date = clean(body.date, 10);
      let link = "";
      try { const u = new URL(String(body.link || "").trim()); if (u.protocol === "https:" || u.protocol === "http:") link = u.href.slice(0, 500); } catch {}
      if (!link) return jsonResponse({ error: "Please add a link to the event (starting with https://)" }, 400, corsHeaders);
      if (name.length < 3) return jsonResponse({ error: "Please add the event's name" }, 400, corsHeaders);
      if (!isValidDateString(date)) return jsonResponse({ error: "Please pick the event's date" }, 400, corsHeaders);
      if (date < new Date().toISOString().slice(0, 10)) return jsonResponse({ error: "That date has already passed" }, 400, corsHeaders);
      if (city.length < 2) return jsonResponse({ error: "Please add the city (or tick Virtual)" }, 400, corsHeaders);
      const genre = String(body.genre || "");
      if (!EVENT_GENRES.includes(genre)) return jsonResponse({ error: "Please pick the genre of the event" }, 400, corsHeaders);
      const genreOther = genre === "other" ? clean(body.genreOther, 40) : "";
      if (genre === "other" && genreOther.length < 2) return jsonResponse({ error: "Please type what kind of event it is" }, 400, corsHeaders);
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const rateKey = `sugrate:${ip}:${Math.floor(Date.now() / 3600000)}`;
      const used = Number(await env.SITE_DATA.get(rateKey) || 0);
      if (!(await isSignedInAnyone()) && used >= EVENT_SUGGESTION_MAX_PER_IP_PER_HOUR) return jsonResponse({ error: "Too many submissions — please try again later" }, 429, corsHeaders);
      const dayKey = `sugday:event:${new Date().toISOString().slice(0, 10)}`;
      const dayCount = Number((await env.SITE_DATA.get(dayKey)) || 0);
      if (dayCount >= EVENT_SUGGESTION_MAX_PENDING) return jsonResponse({ error: "The submission box is full right now — please try again later" }, 503, corsHeaders);
      await env.SITE_DATA.put(rateKey, String(used + 1), { expirationTtl: 3700 });
      await env.SITE_DATA.put(dayKey, String(dayCount + 1), { expirationTtl: 172800 });
      const comments = String(body.comments || "").replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, " ").trim().slice(0, 600);
      const sug = { id: `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`, link, name, date, city, virtual, genre, genreOther, comments, at: Date.now() };
      { const cfg = await readEventFormCfg(); if (cfg.form) { const chk = checkCalAnswers(cfg.form, body.extra); if (chk.error) return jsonResponse({ error: chk.error }, 400, corsHeaders); sug.extra = cfg.form.fields.filter((f) => chk.answers[f.id] !== undefined).map((f) => ({ label: f.label, value: Array.isArray(chk.answers[f.id]) ? chk.answers[f.id].join(", ") : (chk.answers[f.id] && typeof chk.answers[f.id] === "object" ? String(chk.answers[f.id].address || "") : String(chk.answers[f.id])) })); } }
      await env.SITE_DATA.put(`eventsug:${sug.id}`, JSON.stringify(sug));
      notifyAdminOfEventSuggestion(env, ctx, sug);
      return jsonResponse({ ok: true }, 201, corsHeaders);
    }
    // ---- Public: anyone can suggest a resource (title, type, Instagram/WhatsApp link, city or Virtual). Stored for the admin + emailed. ----
    if (path === "/api/resource-suggestions" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (body.website) return jsonResponse({ ok: true }, 200, corsHeaders); // honeypot
      const clean = (v, max) => String(v || "").replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
      const title = clean(body.title, 120);
      const type = String(body.type || "");
      const virtual = body.virtual === true;
      const city = virtual ? "Virtual" : clean(body.city, 60);
      let link = "";
      try {
        let raw = String(body.link || "").trim();
        if (raw && !/^[a-z]+:\/\//i.test(raw)) raw = "https://" + raw;
        const u = new URL(raw);
        const host = u.hostname.replace(/^www\./, "").toLowerCase();
        const ok = ["instagram.com", "wa.me", "whatsapp.com", "chat.whatsapp.com", "api.whatsapp.com"].some((h) => host === h || host.endsWith("." + h));
        if ((u.protocol === "https:" || u.protocol === "http:") && ok) link = u.href.slice(0, 500);
      } catch {}
      if (title.length < 2) return jsonResponse({ error: "Please add the business or resource name" }, 400, corsHeaders);
      if (!RESOURCE_CATEGORIES.includes(type) && type !== "other") return jsonResponse({ error: "Please pick a type" }, 400, corsHeaders);
      const typeOther = type === "other" ? clean(body.typeOther, 40) : "";
      if (type === "other" && typeOther.length < 2) return jsonResponse({ error: "Please type what kind of resource it is" }, 400, corsHeaders);
      if (!link) return jsonResponse({ error: "Please add an Instagram or WhatsApp link" }, 400, corsHeaders);
      if (city.length < 2) return jsonResponse({ error: "Please add the city (or tick Virtual)" }, 400, corsHeaders);
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const rateKey = `sugrate:${ip}:${Math.floor(Date.now() / 3600000)}`;
      const used = Number(await env.SITE_DATA.get(rateKey) || 0);
      if (!(await isSignedInAnyone()) && used >= EVENT_SUGGESTION_MAX_PER_IP_PER_HOUR) return jsonResponse({ error: "Too many submissions — please try again later" }, 429, corsHeaders);
      const dayKey = `sugday:resource:${new Date().toISOString().slice(0, 10)}`;
      const dayCount = Number((await env.SITE_DATA.get(dayKey)) || 0);
      if (dayCount >= EVENT_SUGGESTION_MAX_PENDING) return jsonResponse({ error: "The submission box is full right now — please try again later" }, 503, corsHeaders);
      await env.SITE_DATA.put(rateKey, String(used + 1), { expirationTtl: 3700 });
      await env.SITE_DATA.put(dayKey, String(dayCount + 1), { expirationTtl: 172800 });
      const comments = String(body.comments || "").replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, " ").trim().slice(0, 600);
      const sug = { id: `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`, title, type, typeOther, link, city, virtual, comments, at: Date.now() };
      await env.SITE_DATA.put(`ressug:${sug.id}`, JSON.stringify(sug));
      notifyAdminOfResourceSuggestion(env, ctx, sug);
      return jsonResponse({ ok: true }, 201, corsHeaders);
    }
    // ---- Web Push: a member registers this device ----
    if (path === "/api/push/subscribe" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const sub = body && body.subscription;
      if (!sub || typeof sub.endpoint !== "string" || !/^https:\/\//.test(sub.endpoint) || sub.endpoint.length > 600) return jsonResponse({ error: "Invalid subscription" }, 400, corsHeaders);
      const subs = (await readPushSubs(env, meId)).filter((x) => x.endpoint !== sub.endpoint);
      subs.push({ endpoint: sub.endpoint, at: Date.now() });
      await env.SITE_DATA.put(pushKey(meId), JSON.stringify(subs.slice(-5)));
      return jsonResponse({ ok: true, devices: Math.min(subs.length, 5) }, 200, corsHeaders);
    }
    // Turn notifications off for this member (all their devices); they can turn them back on from Settings.
    if (path === "/api/push/unsubscribe" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      await env.SITE_DATA.delete(pushKey(meId));
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    // The service worker fetches the text of the notification it was just woken for (keyed by a hash of its own endpoint).
    if (path === "/api/push/message" && request.method === "GET") {
      const h = (url.searchParams.get("e") || "").slice(0, 80);
      let msg = null;
      try { msg = JSON.parse((await env.SITE_DATA.get(`pushmsg:${h}`)) || "null"); } catch {}
      return jsonResponse(msg || { title: "4DASISTAS", body: "You have a new update — tap to open.", url: "/" }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    // Fresh membership + pending requests for the signed-in person (the cached session goes stale once an admin approves).
    if (path === "/api/me" && request.method === "GET") {
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      // "last active" for the admin profile view — written at most once an hour per person (KV writes are limited)
      if (!(await touchMember(env, me.id, false)) && (!me.lastSeenAt || Date.now() - me.lastSeenAt > 6 * 3600000)) { me.lastSeenAt = Date.now(); await writeUser(env, me); } // D1 first; the KV fallback is throttled to every 6 h
      const clubs = await allClubIdsContaining(env, me.id);
      let notices = [];
      try { notices = JSON.parse((await env.SITE_DATA.get(`notice:${me.id}`)) || "[]"); } catch {}
      return jsonResponse({ ...publicUser(me), clubs, pending: await pendingClubIdsFor(env, me.id), waitlist: visibleWaitlist(me, clubs), notices, push: (await readPushSubs(env, me.id)).length > 0, notifOff: Array.isArray(me.notifOff) ? me.notifOff : [], phone: me.phone || "", phoneConfirmed: !!(me.phoneConfirmedAt || me.phone), ...(await (async () => {
        // Squads became clubs: which of the four new clubs this person was in as a squad, and whether they've confirmed yet (the /stay page)
        return { stayClubs: await legacySquadClubsOf(env, me.id), stayDone: !!me.stayConfirmedAt };
      })()) }, 200, corsHeaders);
    }
    // The member's customised home page: which optional sections they've hidden (their clubs always show). Kept on their account so it follows them between devices.
    // "Delete my account" (in the app's Edit profile): needs their PIN; removes the profile and everything linked to it.
    if (path === "/api/me/delete-account" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      if (!ideaRateOk(request.headers.get("CF-Connecting-IP") || "x")) return jsonResponse({ error: "Slow down a little — try again in a minute" }, 429, corsHeaders);
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (me.pinHash !== await sha256Hex(String(b.pin || "").trim())) return jsonResponse({ error: "That PIN isn't right" }, 403, corsHeaders);
      await eraseUserEverywhere(env, me);
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    // The native app registers its Apple push token here (stored in D1, no KV writes).
    if (path === "/api/push/apns-register" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const token = String(b.token || "").toLowerCase().replace(/[^0-9a-f]/g, "");
      if (token.length < 32 || token.length > 200) return jsonResponse({ error: "Bad token" }, 400, corsHeaders);
      if (!(await seenEnsure(env))) return jsonResponse({ error: "Not available" }, 503, corsHeaders);
      await env.DB.prepare("INSERT INTO device_tokens (token, user_id, platform, at) VALUES (?, ?, 'ios', ?) ON CONFLICT(token) DO UPDATE SET user_id = excluded.user_id, at = excluded.at").bind(token, meId, Date.now()).run();
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    if (path === "/api/me/prefs" && (request.method === "GET" || request.method === "POST")) {
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      const KEYS = ["todo", "events", "whatson", "steps", "badminton", "links"];
      if (request.method === "POST") {
        let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
        const hidden = [...new Set((Array.isArray(b.hidden) ? b.hidden : []).map(String).filter((k) => KEYS.includes(k)))];
        if (JSON.stringify(hidden) !== JSON.stringify(me.homeHidden || [])) { me.homeHidden = hidden; await writeUser(env, me); }
      }
      return jsonResponse({ hidden: Array.isArray(me.homeHidden) ? me.homeHidden : [] }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    // The signed-in member's "to-do" list for the Clubs home: next events they're going to, unpaid events, undated events waiting for their interest.
    if (path === "/api/me/badge/clear" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      try { await seenEnsure(env); await env.DB.prepare("INSERT INTO badge_counts (user_id, n) VALUES (?, 0) ON CONFLICT(user_id) DO UPDATE SET n = 0").bind(meId).run(); } catch {}
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    // The app asks this on launch: if its build number is below minBuild it shows a polite "please update" screen. Edited by the main admin (Admin page → 📲 Require app update).
    if (path === "/api/app-config" && request.method === "GET") {
      let c = {}; try { c = JSON.parse((await env.SITE_DATA.get("appconfig")) || "{}"); } catch {}
      return jsonResponse({ minBuild: Number(c.minBuild) || 0, storeUrl: c.storeUrl || "https://apps.apple.com/app/id6825452884", message: c.message || "" }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    // "Add to my calendar": a one-event .ics for a club-calendar event (opened in the phone's own calendar sheet)
    { const icsM = path.match(/^\/api\/event-ics\/([^/]+)\/?$/);
      if (icsM && request.method === "GET") {
        const ev = calFind(await readClubCal(env), decodeURIComponent(icsM[1]));
        if (!ev || !ev.date) return new Response("Event not found", { status: 404 });
        const esc = (s) => String(s || "").replace(/\\/g, "\\\\").replace(/[,;]/g, (m) => "\\" + m).replace(/\r?\n/g, "\\n");
        const d0 = ev.date.replace(/-/g, ""), tm = String(ev.time || "").match(/(\d{1,2})(?::(\d{2}))?\s*(am|pm)/i);
        let dt, dtEnd;
        if (tm) { let h = Number(tm[1]) % 12 + (/pm/i.test(tm[3]) ? 12 : 0); const mi = tm[2] || "00", h2 = (h + 2) % 24, pad = (n) => String(n).padStart(2, "0"); dt = `DTSTART;TZID=America/Toronto:${d0}T${pad(h)}${mi}00`; dtEnd = `DTEND;TZID=America/Toronto:${d0}T${pad(h2)}${mi}00`; }
        else { const nx = new Date(ev.date + "T12:00:00Z"); nx.setUTCDate(nx.getUTCDate() + 1); dt = `DTSTART;VALUE=DATE:${d0}`; dtEnd = `DTEND;VALUE=DATE:${nx.toISOString().slice(0, 10).replace(/-/g, "")}`; }
        const body = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//4DS//EN", "BEGIN:VEVENT", `UID:${esc(ev.id)}@4dasistas.ca`, `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, "").slice(0, 15)}Z`, dt, dtEnd, `SUMMARY:${esc(ev.title)}`, ev.place ? `LOCATION:${esc(ev.place)}` : "", `DESCRIPTION:${esc((ev.desc || "") + "\n\nhttps://4dasistas.ca")}`, "END:VEVENT", "END:VCALENDAR"].filter(Boolean).join("\r\n");
        return new Response(body, { headers: { "Content-Type": "text/calendar; charset=utf-8", "Content-Disposition": `inline; filename="event.ics"`, "Cache-Control": "no-store" } });
      } }
    // ---- Event reviews: members rate an activity they attended with hearts (1-5) and leave a comment; the main admin reads them ----
    if (path === "/api/me/reviews" && (request.method === "GET" || request.method === "POST")) {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      if (!env.DB) return jsonResponse({ error: "Reviews aren't available yet" }, 503, corsHeaders);
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS event_reviews (user_id TEXT NOT NULL, event_id TEXT NOT NULL, title TEXT, ev_date TEXT, rating INTEGER NOT NULL, comment TEXT, at INTEGER, PRIMARY KEY (user_id, event_id))").run();
      if (request.method === "GET") {
        const rows = (await env.DB.prepare("SELECT event_id, rating, comment FROM event_reviews WHERE user_id = ?").bind(meId).all()).results || [];
        return jsonResponse({ reviews: rows }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
      }
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const eventId = String(b.eventId || "").slice(0, 120), rating = Math.round(Number(b.rating)), comment = String(b.comment || "").replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "").trim().slice(0, 600);
      if (!eventId || !(rating >= 1 && rating <= 5)) return jsonResponse({ error: "Pick 1 to 5 hearts" }, 400, corsHeaders);
      const ev = (await readClubCal(env)).find((e) => e.id === eventId);
      if (!ev || !(ev.rsvps || []).some((x) => x.id === meId && x.status === "going") || ev.date >= new Date().toISOString().slice(0, 10)) return jsonResponse({ error: "You can only review activities you attended" }, 403, corsHeaders);
      await env.DB.prepare("INSERT INTO event_reviews (user_id, event_id, title, ev_date, rating, comment, at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user_id, event_id) DO UPDATE SET rating = excluded.rating, comment = excluded.comment, at = excluded.at").bind(meId, eventId, String(ev.title || "").slice(0, 120), ev.date, rating, comment, Date.now()).run();
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    if (path === "/api/me/attended" && request.method === "GET") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      const todayIso = new Date().toISOString().slice(0, 10), roster = await readClubRoster(env);
      const activities = (await readClubCal(env)).filter((e) => !e.tbd && e.date < todayIso && (e.rsvps || []).some((x) => x.id === meId && x.status === "going"))
        .sort((a, b) => b.date.localeCompare(a.date)).map((e) => ({ id: e.id, title: e.title, date: e.date, clubs: calClubs(e).map((cid) => (roster.find((c) => c.id === cid) || {}).title).filter(Boolean) }));
      return jsonResponse({ activities }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    if (path === "/api/me/todo" && request.method === "GET") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      const today = new Date().toISOString().slice(0, 10), roster = await readClubRoster(env), mineClubs = [];
      for (const c of roster) if ((await readClubMemberIds(env, c.id)).includes(meId)) mineClubs.push(c.id);
      const title = (e) => calClubs(e).map((id) => (roster.find((c) => c.id === id) || {}).title).filter(Boolean).join(" × ");
      const all = await readClubCal(env), next = [], unpaid = [], tbd = [];
      for (const e of all) {
        if (e.tbd) { if (calClubs(e).some((c) => mineClubs.includes(c)) && !(e.interest || []).some((i) => i.id === meId)) tbd.push({ id: e.id, title: e.title, clubTitle: title(e) }); continue; }
        if (!e.date || e.date < today) continue;
        const r = (e.rsvps || []).find((x) => x.id === meId);
        if (!r || r.status !== "going") continue;
        next.push({ id: e.id, title: e.title, date: e.date, time: e.time || "", place: e.place || "", clubTitle: title(e) });
        if (e.form && e.form.payment && !r.paid) unpaid.push({ id: e.id, title: e.title, date: e.date, amount: (e.form.payment || {}).amount || "" });
      }
      next.sort((a, b) => a.date.localeCompare(b.date) || String(a.time).localeCompare(String(b.time)));
      return jsonResponse({ next: next.slice(0, 3), unpaid: unpaid.slice(0, 5), tbd: tbd.slice(0, 5) }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    // ---- Squads became clubs: existing squad members log in on /#/stay and choose which of the four new clubs to stay in / join ----
    if (path === "/api/me/stay-clubs" && (request.method === "GET" || request.method === "POST")) {
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      const roster = await readClubRoster(env), ids = Object.values(SQUAD_TO_CLUB);
      const had = await legacySquadClubsOf(env, me.id);
      if (request.method === "GET") {
        const pending = await pendingClubIdsFor(env, me.id);
        const options = [];
        for (const id of ids) { const c = roster.find((x) => x.id === id); if (c) options.push({ id, title: c.title, emoji: c.emoji || "", wasIn: had.includes(id), inClub: (await readClubMemberIds(env, id)).includes(me.id), pending: pending.includes(id) }); }
        return jsonResponse({ name: me.name, options, confirmedAt: me.stayConfirmedAt || 0 }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
      }
      let body; try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const want = new Set((Array.isArray(body.clubs) ? body.clubs : []).map(String).filter((id) => ids.includes(id) && roster.some((c) => c.id === id)));
      const joined = [], requested = [];
      for (const id of want) {
        const members = await readClubMemberIds(env, id);
        if (members.includes(me.id)) { joined.push(id); continue; }
        if (had.includes(id)) { await writeClubMemberIds(env, id, [...members, me.id]); joined.push(id); } // they were already in this group chat: no approval needed
        else if (!(await env.SITE_DATA.get(joinReqKey(id, me.id)))) { // a new club for them: the usual join request
          await env.SITE_DATA.put(joinReqKey(id, me.id), JSON.stringify({ at: Date.now() }));
          const club = roster.find((c) => c.id === id); if (club) notifyAdminOfJoinRequest(env, ctx, me, club);
          requested.push(id);
        }
      }
      me.stayConfirmedAt = Date.now(); me.stayChoices = [...want];
      await writeUser(env, me);
      const out = []; for (const id of joined) { const c = roster.find((x) => x.id === id); if (c) out.push({ id, title: c.title, link: c.signup || "" }); }
      return jsonResponse({ ok: true, joined: out, requested }, 200, corsHeaders);
    }
    // Admin "Needs you" counts (main admin): RSVPs awaiting approval, unpaid sign-ups, undated events people are keen on, squad members who haven't confirmed.
    if (path === "/api/admin/needs" && request.method === "GET") {
      const today = new Date().toISOString().slice(0, 10);
      let pendingRsvps = 0, unpaid = 0, tbdKeen = 0, stayTodo = 0;
      for (const e of await readClubCal(env)) {
        if (e.tbd) { if ((e.interest || []).length) tbdKeen++; continue; }
        if (!e.date || e.date < today) continue;
        for (const r of e.rsvps || []) { if (r.status === "pending") pendingRsvps++; else if (r.status === "going" && e.form && e.form.payment && !r.paid && !r.guest) unpaid++; }
      }
      const seen = new Set();
      for (const sid of Object.keys(SQUAD_TITLES)) for (const uid of await readSquadMemberIds(env, sid)) seen.add(uid);
      for (const uid of seen) { const u = await readUser(env, uid); if (u && !u.stayConfirmedAt) stayTodo++; }
      let stepsStuck = 0; try { if (await stepsEnsure(env)) stepsStuck = ((await env.DB.prepare("SELECT COUNT(*) AS n FROM step_participants q LEFT JOIN step_diag d ON d.user_id = q.user_id WHERE (d.ok = 0) OR (SELECT MAX(updated) FROM steps_daily WHERE user_id = q.user_id) IS NULL OR (SELECT MAX(updated) FROM steps_daily WHERE user_id = q.user_id) < ?").bind(Date.now() - 2 * 86400000).first()) || {}).n || 0; } catch {}
      return jsonResponse({ pendingRsvps, unpaid, tbdKeen, stayTodo, stepsStuck }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    // ---- Steps challenge ----
    if (path === "/api/steps/public" && request.method === "GET") {
      if (!(await stepsEnsure(env))) return jsonResponse({ round: null, previous: [] }, 200, corsHeaders);
      const pubData = await stepsPublicData(env), out = { ...pubData, leaderboard: [] };
      if (pubData.round) {
        try {
          const rows = (await env.DB.prepare("SELECT q.user_id AS user_id, COALESCE(SUM(d.steps),0) AS s FROM step_participants q LEFT JOIN steps_daily d ON d.user_id = q.user_id AND d.day BETWEEN ? AND ? WHERE q.round_id = ? GROUP BY q.user_id ORDER BY s DESC LIMIT 8").bind(pubData.round.start, pubData.round.end, pubData.round.id).all()).results || [];
          for (const r of rows) { const u = await readUser(env, r.user_id); out.leaderboard.push({ name: u ? pubName(u.name, u.username) : "member", steps: r.s }); } // visitors see masked names
        } catch {}
      }
      return jsonResponse(out, 200, { ...corsHeaders, "Cache-Control": "public, max-age=60" });
    }
    if (path === "/api/me/steps" && (request.method === "GET" || request.method === "POST")) {
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "Steps aren't available yet" }, 503, corsHeaders);
      const todayUtc = bmToronto(); // 'today' is the member's Toronto day (the UTC date flips at ~8pm and showed 0)
      if (request.method === "POST") {
        // Samples come from the native app reading Apple Health / Health Connect: [{day:'YYYY-MM-DD', steps, source:'apple'|'google'}] (the whole day's total, re-sent each hour).
        let body; try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
        const minDay = new Date(Date.now() - 15 * 86400000).toISOString().slice(0, 10), maxDay = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
        const sr1 = await env.DB.prepare("SELECT source FROM step_sources WHERE user_id = ?").bind(me.id).first(), chosen = (sr1 && sr1.source) || "";
        // ONE source per person: the phone's numbers only count when the member picked this phone's Health app — never mixed with another source
        if (!chosen) return jsonResponse({ ok: false, needsSource: true }, 200, corsHeaders);
        const sentSrc = Array.isArray(body.samples) && body.samples[0] && body.samples[0].source === "google" ? "google" : "apple";
        if (chosen !== sentSrc) return jsonResponse({ ok: true, skipped: chosen }, 200, corsHeaders); // their steps come from Fitbit — the phone's own health data is ignored
        const stmts = [], now = Date.now();
        for (const x of (Array.isArray(body.samples) ? body.samples : []).slice(0, 16)) {
          const steps = Math.round(Number(x && x.steps)), day = String((x && x.day) || ""), src = x && x.source === "apple" ? "apple" : x && x.source === "google" ? "google" : "";
          if (!isValidDateString(day) || day < minDay || day > maxDay || !src || !Number.isFinite(steps) || steps < 0) continue;
          stmts.push(env.DB.prepare("INSERT INTO steps_daily (user_id, day, steps, source, updated) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, day) DO UPDATE SET steps = excluded.steps, source = excluded.source, updated = excluded.updated").bind(me.id, day, Math.min(steps, STEP_MAX_PER_DAY), src, now));
        }
        if (!stmts.length) return jsonResponse({ error: "No valid step data" }, 400, corsHeaders);
        await env.DB.batch(stmts); _stepsPublicMemo = { at: 0, data: null };
        await stepDiag(env, me.id, true, "Synced " + stmts.length + " days from " + (body.samples[0] && body.samples[0].source === "google" ? "Health Connect" : "Apple Health"));
        return jsonResponse({ ok: true, saved: stmts.length }, 200, corsHeaders);
      }
      try { const sr0 = await env.DB.prepare("SELECT source FROM step_sources WHERE user_id = ?").bind(me.id).first(); if (sr0 && sr0.source === "googlehealth") { const lu = await env.DB.prepare("SELECT MAX(updated) AS u FROM steps_daily WHERE user_id = ?").bind(me.id).first(); if (url.searchParams.get("sync") === "1" || !lu || !lu.u || Date.now() - lu.u > 2 * 60000) await ghSync(env, me.id); } } catch (e) { if (url.searchParams.get("sync") === "1") return jsonResponse({ error: String((e && e.message) || e) }, 502, corsHeaders); }
      const pub = await stepsPublicData(env), round = pub.round;
      const out = { ...pub, mine: { round: 0, today: 0, lastSync: 0, rank: null, joined: false, source: "" }, leaderboard: [], pledges: [] };
      { const sr = await env.DB.prepare("SELECT source, goal FROM step_sources WHERE user_id = ?").bind(me.id).first().catch(() => null); out.mine.source = (sr && sr.source) || ""; out.mine.goal = (sr && sr.goal) || 10000; }
      try { await ghEnsure(env); out.mine.ghConnected = !!(await env.DB.prepare("SELECT 1 AS x FROM gh_tokens WHERE user_id = ?").bind(me.id).first()); } catch { out.mine.ghConnected = false; }
      { const dg = await env.DB.prepare("SELECT at, ok, msg FROM step_diag WHERE user_id = ?").bind(me.id).first().catch(() => null); out.mine.diag = dg ? { at: dg.at, ok: !!dg.ok, msg: dg.msg } : null; }
      const last = await env.DB.prepare("SELECT MAX(updated) AS u FROM steps_daily WHERE user_id = ?").bind(me.id).first(); out.mine.lastSync = (last && last.u) || 0;
      if (round) {
        out.mine.joined = !!(await env.DB.prepare("SELECT 1 AS x FROM step_participants WHERE round_id = ? AND user_id = ?").bind(round.id, me.id).first());
        const rows = (await env.DB.prepare("SELECT q.user_id AS user_id, COALESCE(SUM(d.steps),0) AS s FROM step_participants q LEFT JOIN steps_daily d ON d.user_id = q.user_id AND d.day BETWEEN ? AND ? WHERE q.round_id = ? GROUP BY q.user_id ORDER BY s DESC").bind(round.start, round.end, round.id).all()).results || [];
        const idx = rows.findIndex((r) => r.user_id === me.id);
        if (idx >= 0) { out.mine.round = rows[idx].s; out.mine.rank = idx + 1; }
        const td = await env.DB.prepare("SELECT steps FROM steps_daily WHERE user_id = ? AND day = ?").bind(me.id, todayUtc).first(); out.mine.today = (td && td.steps) || 0;
        for (const r of rows.slice(0, 30)) { const u = await readUser(env, r.user_id); out.leaderboard.push({ name: u ? pubName(u.name, u.username) : "member", u: u ? u.username || "" : "", steps: r.s, me: r.user_id === me.id }); }
        const pl = (await env.DB.prepare("SELECT id, name, user_id, per1000, cap FROM step_pledges WHERE round_id = ? ORDER BY at").bind(round.id).all()).results || [];
        out.pledges = pl.map((x) => ({ id: x.id, name: x.name, per1000: x.per1000, cap: x.cap, mine: x.user_id === me.id }));
      }
      return jsonResponse(out, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    if (path === "/api/me/steps/join" && (request.method === "POST" || request.method === "DELETE")) {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "Steps aren't available yet" }, 503, corsHeaders);
      const round = (await stepsPublicData(env)).round;
      if (!round) return jsonResponse({ error: "There's no challenge right now" }, 400, corsHeaders);
      if (request.method === "DELETE") { await env.DB.prepare("DELETE FROM step_participants WHERE round_id = ? AND user_id = ?").bind(round.id, meId).run(); _stepsPublicMemo = { at: 0, data: null }; return jsonResponse({ ok: true }, 200, corsHeaders); }
      if (round.status === "finished") return jsonResponse({ error: "This challenge has finished" }, 400, corsHeaders);
      if (round.mode === "invite" && !(await env.DB.prepare("SELECT 1 AS x FROM step_participants WHERE round_id = ? AND user_id = ?").bind(round.id, meId).first())) return jsonResponse({ error: "This challenge is invite-only — ask an admin to add you" }, 403, corsHeaders);
      await env.DB.prepare("INSERT OR IGNORE INTO step_participants (round_id, user_id, at, added) VALUES (?, ?, ?, 0)").bind(round.id, meId, Date.now()).run();
      _stepsPublicMemo = { at: 0, data: null };
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    if (path === "/api/me/google/start" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      if (!(await ghEnsure(env))) return jsonResponse({ error: "Google Health isn't switched on yet — the site owner needs to finish setting it up" }, 503, corsHeaders);
      const ts = Date.now(), sig = (await hmacHex(`google-state:${env.GOOGLE_CLIENT_SECRET}`, `${meId}.${ts}`)).slice(0, 32);
      const u = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      u.search = new URLSearchParams({ response_type: "code", client_id: env.GOOGLE_CLIENT_ID, redirect_uri: ghRedirect(env), scope: "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly", access_type: "offline", prompt: "consent", include_granted_scopes: "true", state: `${meId}.${ts}.${sig}` }).toString();
      return jsonResponse({ url: u.toString() }, 200, corsHeaders);
    }
    if (path === "/api/google/callback" && request.method === "GET") {
      const page = (msg, ok) => new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;background:#fef7f4;color:#373d3b;text-align:center;padding:64px 24px"><div style="font-size:54px">${ok ? "✅" : "⚠️"}</div><h2>${msg}</h2><p>${ok ? "All set! Tap <b>Done</b> (top corner) to go back — your steps are already syncing." : "Tap <b>Done</b> (top corner) and try again."}</p><script>setTimeout(function(){try{window.close()}catch(e){}},1200)</script>`, { status: ok ? 200 : 400, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
      try {
        if (!(await ghEnsure(env)) || !(await stepsEnsure(env))) return page("Not set up yet", false);
        const [uid, ts, sig] = String(url.searchParams.get("state") || "").split(".");
        const want = uid && ts ? (await hmacHex(`google-state:${env.GOOGLE_CLIENT_SECRET}`, `${uid}.${ts}`)).slice(0, 32) : "";
        if (!url.searchParams.get("code") || !want || !sameSig(sig, want) || Date.now() - Number(ts) > 30 * 60000) return page("That link expired", false);
        const j = await ghToken(env, { grant_type: "authorization_code", code: url.searchParams.get("code"), redirect_uri: ghRedirect(env) });
        await env.DB.prepare("INSERT INTO gh_tokens (user_id, access, refresh, exp, at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET access = excluded.access, refresh = COALESCE(excluded.refresh, gh_tokens.refresh), exp = excluded.exp, at = excluded.at").bind(uid, j.access_token, j.refresh_token || null, Date.now() + (j.expires_in || 3600) * 1000, Date.now()).run();
        await env.DB.prepare("INSERT INTO step_sources (user_id, source, at) VALUES (?, 'googlehealth', ?) ON CONFLICT(user_id) DO UPDATE SET source = 'googlehealth', at = excluded.at").bind(uid, Date.now()).run();
        try { await ghSync(env, uid); } catch {}
        return page("Google Health connected", true);
      } catch (e) { return page("Couldn't connect Google Health", false); }
    }
    if (path === "/api/me/google/sync" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      try { const n = await ghSync(env, meId); return jsonResponse({ ok: true, days: n }, 200, corsHeaders); } catch (e) { return jsonResponse({ error: e.message }, 502, corsHeaders); }
    }
    if (path === "/api/me/steps/history" && request.method === "GET") { // last 7 days for me, or for anyone in the current challenge (signed-in members only)
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "Steps aren't available yet" }, 503, corsHeaders);
      const want = String(url.searchParams.get("u") || "").trim().toLowerCase();
      let target = me;
      if (want && want !== String(me.username || "").toLowerCase()) {
        const tid = await findUserIdByUsername(env, want); const tu = tid ? await readUser(env, tid) : null;
        if (!tu) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
        const pub = await stepsPublicData(env), round = pub.round;
        const inRound = round && (await env.DB.prepare("SELECT 1 AS x FROM step_participants WHERE round_id = ? AND user_id = ?").bind(round.id, tu.id).first());
        if (!inRound) return jsonResponse({ error: "Only people in the current challenge can be viewed" }, 403, corsHeaders);
        target = tu;
      }
      const days = [], mo = String(url.searchParams.get("month") || "");
      if (/^\d{4}-\d{2}$/.test(mo)) { // a whole month: from October 2026 up to next month only
        const now = bmToronto(), [ny, nm] = now.split("-").map(Number), next = `${nm === 12 ? ny + 1 : ny}-${String(nm === 12 ? 1 : nm + 1).padStart(2, "0")}`;
        if (mo < "2026-10" || mo > next) return jsonResponse({ error: "That month isn't available" }, 400, corsHeaders);
        const [y, m] = mo.split("-").map(Number), n = new Date(Date.UTC(y, m, 0)).getUTCDate();
        for (let d = 1; d <= n; d++) days.push(`${mo}-${String(d).padStart(2, "0")}`);
      } else for (let i = 6; i >= 0; i--) days.push(bmToronto(new Date(Date.now() - i * 86400000)));
      const rows = (await env.DB.prepare("SELECT day, steps FROM steps_daily WHERE user_id = ? AND day BETWEEN ? AND ?").bind(target.id, days[0], days[days.length - 1]).all()).results || [];
      const by = {}; for (const r of rows) by[r.day] = r.steps;
      const sr = await env.DB.prepare("SELECT source FROM step_sources WHERE user_id = ?").bind(target.id).first();
      return jsonResponse({ name: target.id === me.id ? "You" : pubName(target.name, target.username), me: target.id === me.id, month: /^\d{4}-\d{2}$/.test(mo) ? mo : "", today: bmToronto(), source: (sr && sr.source) || "", days: days.map((d) => ({ day: d, steps: by[d] || 0 })) }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    if (path === "/api/me/badminton/checkin" && request.method === "POST") { // check-in from Settings: needs the badminton password (the one on the iPad kiosk), so it only happens when the admin allows it
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      if (!ideaRateOk((request.headers.get("CF-Connecting-IP") || "x") + ":bmci")) return jsonResponse({ error: "Too many tries — wait a minute" }, 429, corsHeaders);
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!(await bmKioskOk(env, b.password))) return jsonResponse({ error: "That password isn't right — ask the admin" }, 403, corsHeaders);
      if (!(await bmEnsure(env))) return jsonResponse({ error: "Badminton isn't available yet" }, 503, corsHeaders);
      const row = await env.DB.prepare("SELECT id FROM bm_players WHERE uid = ?").bind(me.id).first();
      if (!row && !(await readClubMemberIds(env, "club-badminton")).includes(me.id)) return jsonResponse({ error: "Join the Badminton club first" }, 403, corsHeaders);
      const pl = await bmPlayerFor(env, me), day = bmToronto(), present = b.undo ? false : true;
      await env.DB.prepare("INSERT OR REPLACE INTO bm_attendance (id, day, data) VALUES (?, ?, ?)").bind(`${pl.id}:${day}`, day, JSON.stringify({ id: `${pl.id}:${day}`, player_id: pl.id, session_date: day, present })).run();
      return jsonResponse({ ok: true, checkedIn: present, day }, 200, corsHeaders);
    }
    if (path === "/api/me/steps/goal" && request.method === "POST") { // personal daily goal
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const goal = Math.round(Number(b.goal)); if (!Number.isFinite(goal) || goal < 500 || goal > 60000) return jsonResponse({ error: "Pick a goal between 500 and 60,000 steps" }, 400, corsHeaders);
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "Steps aren't available yet" }, 503, corsHeaders);
      await env.DB.prepare("INSERT INTO step_sources (user_id, source, at, goal) VALUES (?, '', ?, ?) ON CONFLICT(user_id) DO UPDATE SET goal = excluded.goal").bind(meId, Date.now(), goal).run();
      return jsonResponse({ ok: true, goal }, 200, corsHeaders);
    }
    if (path === "/api/me/steps/diag" && request.method === "POST") { // the app reports why a Health read found nothing / failed
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "Steps aren't available yet" }, 503, corsHeaders);
      await stepDiag(env, meId, !!b.ok, String(b.msg || "").replace(/[<>]/g, "").slice(0, 240));
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    if (path === "/api/me/steps/source" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const source = b.source === "apple" ? "apple" : b.source === "google" ? "google" : b.source === "googlehealth" ? "googlehealth" : "";
      if (!source || !(await stepsEnsure(env))) return jsonResponse({ error: "Choose Apple Health or Google Health Connect" }, 400, corsHeaders);
      await env.DB.prepare("INSERT INTO step_sources (user_id, source, at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET source = excluded.source, at = excluded.at").bind(meId, source, Date.now()).run();
      // switching source: the last two weeks from any OTHER source are removed, so a day is never a mix (the new source refills them right away)
      await env.DB.prepare("DELETE FROM steps_daily WHERE user_id = ? AND source != ? AND day >= ?").bind(meId, source, new Date(Date.now() - 15 * 86400000).toISOString().slice(0, 10)).run();
      let needsConnect = false, err = "";
      if (source === "googlehealth") { // already connected → pull the Google numbers right now (they replace whatever the phone sent before)
        let has = false; try { await ghEnsure(env); has = !!(await env.DB.prepare("SELECT 1 AS x FROM gh_tokens WHERE user_id = ?").bind(meId).first()); } catch {}
        if (!has) needsConnect = true; else { try { await ghSync(env, meId); } catch (e) { err = String((e && e.message) || e); if (/reconnect/i.test(err)) needsConnect = true; } }
      }
      _stepsPublicMemo = { at: 0, data: null };
      return jsonResponse({ ok: true, source, needsConnect, error: err }, 200, corsHeaders);
    }
    if (path === "/api/me/steps/pledge" && (request.method === "POST" || request.method === "DELETE")) {
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Please log in first" }, 401, corsHeaders);
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "Steps aren't available yet" }, 503, corsHeaders);
      const round = (await stepsPublicData(env)).round;
      if (!round || round.status === "finished") return jsonResponse({ error: "There's no open round to pledge to" }, 400, corsHeaders);
      await env.DB.prepare("DELETE FROM step_pledges WHERE round_id = ? AND user_id = ?").bind(round.id, me.id).run();
      if (request.method === "POST") {
        let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
        const per1000 = Math.round(Number(b.per1000) * 100) / 100, cap = b.cap === "" || b.cap == null ? null : Math.round(Number(b.cap) * 100) / 100;
        if (!Number.isFinite(per1000) || per1000 <= 0 || per1000 > 25) return jsonResponse({ error: "Pledge between $0.01 and $25 per 1,000 steps" }, 400, corsHeaders);
        if (cap !== null && (!Number.isFinite(cap) || cap <= 0 || cap > 5000)) return jsonResponse({ error: "The maximum must be between $1 and $5,000" }, 400, corsHeaders);
        await env.DB.prepare("INSERT INTO step_pledges (id, round_id, name, user_id, per1000, cap, at) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), round.id, firstNameOnly(me.name), me.id, per1000, cap, Date.now()).run();
      }
      _stepsPublicMemo = { at: 0, data: null };
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    if (path === "/api/admin/steps" && request.method === "GET") {
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "No database attached" }, 503, corsHeaders);
      const rounds = (await readStepRounds(env)).sort((a, b) => b.start.localeCompare(a.start)), out = [];
      for (const r of rounds) out.push({ ...r, ...(await stepRoundTotals(env, r)), pledgeList: ((await env.DB.prepare("SELECT id, name, per1000, cap, user_id FROM step_pledges WHERE round_id = ? ORDER BY at").bind(r.id).all()).results || []).map((x) => ({ id: x.id, name: x.name, per1000: x.per1000, cap: x.cap, member: !!x.user_id })),
        participantList: await (async () => { const rows = (await env.DB.prepare("SELECT q.user_id AS user_id, q.added AS added, COALESCE(SUM(d.steps),0) AS s FROM step_participants q LEFT JOIN steps_daily d ON d.user_id = q.user_id AND d.day BETWEEN ? AND ? WHERE q.round_id = ? GROUP BY q.user_id ORDER BY s DESC").bind(r.start, r.end, r.id).all()).results || [], list = []; for (const x of rows) { const u = await readUser(env, x.user_id); const sr = await env.DB.prepare("SELECT source FROM step_sources WHERE user_id = ?").bind(x.user_id).first(), lu = await env.DB.prepare("SELECT MAX(updated) AS u FROM steps_daily WHERE user_id = ?").bind(x.user_id).first(), dg = await env.DB.prepare("SELECT at, ok, msg FROM step_diag WHERE user_id = ?").bind(x.user_id).first().catch(() => null); list.push({ id: x.user_id, name: u ? u.name : "(deleted)", username: u ? u.username : "", steps: x.s, added: !!x.added, source: (sr && sr.source) || "", lastSync: (lu && lu.u) || 0, diag: dg ? { at: dg.at, ok: !!dg.ok, msg: dg.msg } : null }); } return list; })() });
      return jsonResponse({ rounds: out }, 200, corsHeaders);
    }
    if (path === "/api/admin/step-rounds" && request.method === "PUT") {
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const rounds = (Array.isArray(b.rounds) ? b.rounds : []).slice(0, 60).map(cleanStepRound);
      if (rounds.some((r) => !r)) return jsonResponse({ error: "Every round needs a start date and an end date after it" }, 400, corsHeaders);
      await env.SITE_DATA.put(STEP_ROUNDS_KEY, JSON.stringify(rounds)); _stepsPublicMemo = { at: 0, data: null };
      return jsonResponse({ ok: true, rounds }, 200, corsHeaders);
    }
    if (path === "/api/admin/step-pledges" && request.method === "POST") {
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "No database attached" }, 503, corsHeaders);
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const per1000 = Math.round(Number(b.per1000) * 100) / 100, cap = b.cap === "" || b.cap == null ? null : Math.round(Number(b.cap) * 100) / 100;
      if (!(await readStepRounds(env)).some((r) => r.id === b.roundId) || !Number.isFinite(per1000) || per1000 <= 0 || per1000 > 100 || (cap !== null && !(cap > 0))) return jsonResponse({ error: "Check the round and amounts" }, 400, corsHeaders);
      await env.DB.prepare("INSERT INTO step_pledges (id, round_id, name, user_id, per1000, cap, at) VALUES (?, ?, ?, NULL, ?, ?, ?)").bind(crypto.randomUUID(), String(b.roundId), cleanCalText(b.name, 40) || "Sponsor", per1000, cap, Date.now()).run();
      _stepsPublicMemo = { at: 0, data: null };
      return jsonResponse({ ok: true }, 201, corsHeaders);
    }
    if (path === "/api/admin/step-participants" && request.method === "POST") {
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "No database attached" }, 503, corsHeaders);
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const round = (await readStepRounds(env)).find((r) => r.id === b.roundId); if (!round) return jsonResponse({ error: "Unknown challenge" }, 404, corsHeaders);
      let ids = (Array.isArray(b.userIds) ? b.userIds : []).map(String);
      if (b.clubId) ids = ids.concat(await readClubMemberIds(env, String(b.clubId)));
      if (b.everyone) ids = ids.concat((await listAllUsers(env)).map((u) => u.id));
      ids = [...new Set(ids)].slice(0, 1000);
      const existing = new Set(((await env.DB.prepare("SELECT user_id FROM step_participants WHERE round_id = ?").bind(round.id).all()).results || []).map((x) => x.user_id)), added = [];
      const stmts = []; for (const id of ids) { if (existing.has(id)) continue; if (!(await readUser(env, id))) continue; added.push(id); stmts.push(env.DB.prepare("INSERT OR IGNORE INTO step_participants (round_id, user_id, at, added) VALUES (?, ?, ?, 1)").bind(round.id, id, Date.now())); }
      for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
      _stepsPublicMemo = { at: 0, data: null };
      if (b.notify !== false) for (const id of added.slice(0, 200)) ctx.waitUntil(sendPushToUser(env, id, { title: "You're in the challenge! 👟", body: `You were added to ${round.title}. Open 4DS to connect your steps.`, url: "/#/steps", cat: "events" }).catch(() => {}));
      return jsonResponse({ ok: true, added: added.length }, 200, corsHeaders);
    }
    const stepPartDel = path.match(/^\/api\/admin\/step-participants\/([^/]+)\/([^/]+)\/?$/);
    if (stepPartDel && request.method === "DELETE") {
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "No database attached" }, 503, corsHeaders);
      await env.DB.prepare("DELETE FROM step_participants WHERE round_id = ? AND user_id = ?").bind(decodeURIComponent(stepPartDel[1]), decodeURIComponent(stepPartDel[2])).run(); _stepsPublicMemo = { at: 0, data: null };
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    const stepPledgeDel = path.match(/^\/api\/admin\/step-pledges\/([^/]+)\/?$/);
    if (stepPledgeDel && request.method === "DELETE") {
      if (!(await stepsEnsure(env))) return jsonResponse({ error: "No database attached" }, 503, corsHeaders);
      await env.DB.prepare("DELETE FROM step_pledges WHERE id = ?").bind(decodeURIComponent(stepPledgeDel[1])).run(); _stepsPublicMemo = { at: 0, data: null };
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    // ---- Badminton import (main admin): one-time move of the old site's tables. Replaces what's stored; players are matched to 4DS accounts by phone number. ----
    if (path === "/api/admin/badminton/import" && request.method === "POST") {
      if (!(await bmEnsure(env))) return jsonResponse({ error: "No database attached" }, 503, corsHeaders);
      let body; try { body = await request.json(); } catch { return jsonResponse({ error: "That file isn't valid" }, 400, corsHeaders); }
      const counts = {}, now = Date.now();
      for (const [key, table] of Object.entries(BM_TABLES)) {
        const rows = Array.isArray(body[key]) ? body[key] : null;
        if (!rows) { counts[key] = null; continue; } // table not in the file: leave what's stored
        const prepared = [];
        for (let i = 0; i < rows.length; i++) {
          const r = rows[i]; if (!r || typeof r !== "object") continue;
          const id = await bmRowId(table, r, i);
          if (key === "players") { const { pin, ...safe } = r; prepared.push(env.DB.prepare("INSERT OR REPLACE INTO bm_players (id, uid, data) VALUES (?, (SELECT uid FROM bm_players WHERE id = ?), ?)").bind(id, id, JSON.stringify(safe))); } // (a PIN, if the file had one, is never stored)
          else prepared.push(env.DB.prepare(`INSERT OR REPLACE INTO ${table} (id, day, data) VALUES (?, ?, ?)`).bind(id, bmDay(r), JSON.stringify(r)));
        }
        if (key !== "players") await env.DB.prepare(`DELETE FROM ${table}`).run();
        for (let i = 0; i < prepared.length; i += 50) await env.DB.batch(prepared.slice(i, i + 50));
        counts[key] = prepared.length;
      }
      await env.DB.prepare("INSERT OR REPLACE INTO bm_meta (k, v) VALUES ('imported_at', ?)").bind(String(now)).run();
      // Match players to 4DS accounts by phone number (last 10 digits).
      const byPhone = new Map(); for (const u of await listAllUsers(env)) { const d = bmDigits(u.phone); if (d.length >= 7) byPhone.set(d, u); }
      const pl = (await env.DB.prepare("SELECT id, uid, data FROM bm_players").all()).results || [], matched = [], unmatched = [], stmts = [];
      for (const r of pl) { let d; try { d = JSON.parse(r.data); } catch { continue; } const u = byPhone.get(bmDigits(d.phone || d.username)); if (u) { matched.push(d.full_name || d.name); if (r.uid !== u.id) stmts.push(env.DB.prepare("UPDATE bm_players SET uid = ? WHERE id = ?").bind(u.id, r.id)); } else if (!r.uid) unmatched.push(d.full_name || d.name || r.id); }
      for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
      return jsonResponse({ ok: true, counts, matched: matched.length, unmatched }, 200, corsHeaders);
    }
    // Admin: who was in a squad and has / hasn't confirmed yet (to chase on WhatsApp)
    if (path === "/api/admin/stay-status" && request.method === "GET") {
      const roster = await readClubRoster(env), seen = new Map();
      for (const sid of Object.keys(SQUAD_TITLES)) for (const uid of await readSquadMemberIds(env, sid)) seen.set(uid, [...(seen.get(uid) || []), SQUAD_TO_CLUB[sid]]);
      const people = [];
      for (const [uid, had] of seen) {
        const u = await readUser(env, uid); if (!u) continue;
        const title = (id) => (roster.find((c) => c.id === id) || {}).title || id;
        people.push({ id: u.id, name: u.name, username: u.username, phone: u.phone || "", had: had.map(title), confirmedAt: u.stayConfirmedAt || 0, chose: (u.stayChoices || []).map(title) });
      }
      people.sort((a, b) => (a.confirmedAt ? 1 : 0) - (b.confirmedAt ? 1 : 0) || String(a.name).localeCompare(String(b.name)));
      return jsonResponse({ people }, 200, corsHeaders);
    }
    // A member logs out: invalidate their token on the server too (clearing it in the browser alone left it valid).
    if (path === "/api/logout" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      if (token) await env.SITE_DATA.delete(`membersession:${token}`);
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    // A member confirms (or enters) their own phone number — asked once at sign-in, saved to their profile for the admins.
    if (path === "/api/me/phone" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const phone = sanitizePhone(body.phone);
      if (!phone) return jsonResponse({ error: "That doesn't look like a phone number — please include the area code." }, 400, corsHeaders);
      me.phone = phone; me.phoneConfirmedAt = Date.now();
      await writeUser(env, me);
      return jsonResponse({ ok: true, phone }, 200, corsHeaders);
    }
    if (path === "/api/me/notices/ack" && request.method === "POST") {
      const meId = await memberIdFromRequest();
      if (!meId) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      await env.SITE_DATA.delete(`notice:${meId}`);
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    const joinReqMatch = path.match(/^\/api\/clubs\/([^/]+)\/join-request\/?$/);
    if (joinReqMatch && request.method === "POST") {
      const meId = await memberIdFromRequest();
      const me = meId ? await readUser(env, meId) : null;
      if (!me) return jsonResponse({ error: "Sign in to request to join a club" }, 401, corsHeaders);
      const clubId = decodeURIComponent(joinReqMatch[1]);
      const club = (await readClubRoster(env)).find((c) => c.id === clubId);
      if (!club) return jsonResponse({ error: "Unknown club" }, 404, corsHeaders);
      if ((await readClubMemberIds(env, clubId)).includes(me.id)) return jsonResponse({ error: "You're already in this club" }, 409, corsHeaders);
      const pending = await pendingClubIdsFor(env, me.id);
      if (pending.includes(clubId)) return jsonResponse({ ok: true, pending }, 200, corsHeaders);
      if (pending.length >= JOIN_REQUESTS_MAX_PENDING_PER_PERSON) return jsonResponse({ error: "You have several requests waiting already — please wait for an admin to answer them" }, 429, corsHeaders);
      await env.SITE_DATA.put(joinReqKey(clubId, me.id), JSON.stringify({ at: Date.now() }));
      notifyAdminOfJoinRequest(env, ctx, me, club);
      return jsonResponse({ ok: true, pending: [...pending, clubId] }, 201, corsHeaders);
    }
    const membersListMatch = path === "/api/members" || path === "/api/members/";
    const memberProfileMatch = path.match(/^\/api\/members\/([^/]+)\/?$/);
    if ((membersListMatch || memberProfileMatch) && request.method === "GET") {
      if (!(await memberIdFromRequest())) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      if (memberProfileMatch) {
        const id = decodeURIComponent(memberProfileMatch[1]);
        const user = await readUser(env, id);
        if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
        const clubs = await allClubIdsContaining(env, id);
        return jsonResponse({ id: user.id, name: user.name, photo: user.photo || null, clubs }, 200, corsHeaders);
      }
      const clubsByUser = {};
      for (const clubId of await clubIdList(env)) {
        for (const id of await readClubMemberIds(env, clubId)) (clubsByUser[id] = clubsByUser[id] || []).push(clubId);
      }
      const members = [];
      for (const u of await listAllUsers(env)) {
        if (!clubsByUser[u.id] || !u.name) continue; // profiles with no club aren't listed
        members.push({ id: u.id, name: u.name, hasPhoto: !!u.photo, clubs: clubsByUser[u.id] });
      }
      members.sort((a, b) => a.name.localeCompare(b.name));
      return jsonResponse({ members }, 200, corsHeaders);
    }

    const cmAvailabilityMatch = path.match(/^\/api\/clubs\/([^/]+)\/availability\/([^/]+)\/?$/);
    if (cmAvailabilityMatch && (request.method === "GET" || request.method === "PUT")) {
      const clubId = decodeURIComponent(cmAvailabilityMatch[1]);
      const userId = decodeURIComponent(cmAvailabilityMatch[2]);
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      if (!(await verifyMemberToken(env, userId, token))) return jsonResponse({ error: "Not signed in" }, 401, corsHeaders);
      const memberIds = await readClubMemberIds(env, clubId);
      if (!memberIds.includes(userId)) return jsonResponse({ error: "Not a member of this club" }, 403, corsHeaders);
      const key = clubAvailabilityKey(clubId, userId);
      if (request.method === "GET") {
        const raw = await env.SITE_DATA.get(key);
        let days = {};
        try { days = raw ? JSON.parse(raw) : {}; } catch { days = {}; }
        return jsonResponse({ days }, 200, corsHeaders);
      }
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const days = sanitizeAvailabilityDays(body.days);
      await env.SITE_DATA.put(key, JSON.stringify(days));
      return jsonResponse({ days }, 200, corsHeaders);
    }

    // ---- Auth helpers ----

    const getSessionToken = (req) => {
      const cookie = req.headers.get("Cookie") || "";
      const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
      return match ? match[1] : null;
    };

    const isValidSession = async (token) => {
      if (!token) return false;
      const raw = await env.SITE_DATA.get(`session:${token}`);
      if (!raw) return false;
      try {
        const session = JSON.parse(raw);
        if (session.expiresAt && Date.now() > session.expiresAt) {
          await env.SITE_DATA.delete(`session:${token}`);
          return false;
        }
        return true;
      } catch {
        return false;
      }
    };

    const createSession = async () => {
      const token =
        typeof crypto !== "undefined" && crypto.randomUUID
          ? crypto.randomUUID()
          : Math.random().toString(36).slice(2) + Date.now().toString(36);
      const session = {
        expiresAt: Date.now() + SESSION_TTL * 1000,
        createdAt: Date.now(),
      };
      await env.SITE_DATA.put(
        `session:${token}`,
        JSON.stringify(session),
        { expirationTtl: SESSION_TTL }
      );
      return token;
    };

    const setSessionCookie = (token) => {
      return `session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`;
    };

    const clearSessionCookie = () => {
      return "session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
    };

    // ---- Login ----

    if (path === "/login" && request.method === "POST") {
      // Fail closed: if the ADMIN_PASSWORD secret is not configured, never grant a session.
      if (!ADMIN_PASSWORD) {
        const headers = new Headers(corsHeaders);
        headers.set("Location", "/editor?error=2");
        return new Response(null, { status: 302, headers });
      }
      const formData = await request.formData();
      const password = formData.get("password");
      if (password && password === ADMIN_PASSWORD) {
        const token = await createSession();
        const headers = new Headers(corsHeaders);
        headers.set("Set-Cookie", setSessionCookie(token));
        headers.set("Location", "/editor");
        return new Response(null, { status: 302, headers });
      }
      const headers = new Headers(corsHeaders);
      headers.set("Location", "/editor?error=1");
      return new Response(null, { status: 302, headers });
    }

    // ---- Logout ----

    if (path === "/logout") {
      const token = getSessionToken(request);
      if (token) {
        await env.SITE_DATA.delete(`session:${token}`).catch(() => {});
      }
      const headers = new Headers(corsHeaders);
      headers.set("Set-Cookie", clearSessionCookie());
      headers.set("Location", "/editor");
      return new Response(null, { status: 302, headers });
    }

    // ---- JSON admin auth (used by the in-site admin panel under GALS CLUBS) ----

    if (path === "/api/admin/login" && request.method === "POST") {
      if (!ADMIN_PASSWORD) return jsonResponse({ error: "Server misconfigured: ADMIN_PASSWORD is not set" }, 500, corsHeaders);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (String(body.password || "") !== ADMIN_PASSWORD) return jsonResponse({ error: "Incorrect password" }, 401, corsHeaders);
      const token = await createSession();
      const headers = new Headers({ "Content-Type": "application/json", ...corsHeaders });
      headers.set("Set-Cookie", setSessionCookie(token));
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (path === "/api/admin/logout" && request.method === "POST") {
      const token = getSessionToken(request);
      if (token) await env.SITE_DATA.delete(`session:${token}`).catch(() => {});
      const headers = new Headers({ "Content-Type": "application/json", ...corsHeaders });
      headers.set("Set-Cookie", clearSessionCookie());
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    // ================= Badminton compatibility layer (see BM_* helpers): serves the ORIGINAL badminton app that now lives at /badminton.html =================
    if ((path.startsWith("/api/bm/") || path.startsWith("/api/admin/badminton/")) && request.method !== "GET" && !(path === "/api/bm/q")) bmCacheClear(); // any write-capable call starts from fresh data
    if (path.startsWith("/api/bm/") || path.startsWith("/api/admin/badminton/") || path.startsWith("/storage/v1/object/public/profile-avatars/")) {
      if (!(await bmEnsure(env))) return jsonResponse({ error: "Badminton isn't available yet" }, 503, corsHeaders);
      const bmErr = (m, st = 400) => jsonResponse({ error: { message: m } }, st, corsHeaders);
      // Public photos (profile pictures are public, as they were on the old site).
      if (path.startsWith("/storage/v1/object/public/profile-avatars/") && request.method === "GET") {
        const fp = decodeURIComponent(path.slice("/storage/v1/object/public/profile-avatars/".length));
        const f = await env.DB.prepare("SELECT ctype, b64 FROM bm_files WHERE path = ?").bind(fp).first();
        if (!f) return new Response("Not found", { status: 404, headers: corsHeaders });
        const bin = Uint8Array.from(atob(f.b64), (c) => c.charCodeAt(0));
        return new Response(bin, { status: 200, headers: { ...corsHeaders, "Content-Type": f.ctype || "image/jpeg", "Cache-Control": "public, max-age=3600" } });
      }
      // ---- main admin: coach password, iPad kiosk key, status, copy photos over from the old site ----
      if (path === "/api/admin/badminton/status" && request.method === "GET") {
        const t = async (k) => (await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${BM_TBL[k]}`).first()).n;
        const left = (await env.DB.prepare("SELECT COUNT(*) AS n FROM bm_players WHERE json_extract(data, '$.avatar_url') LIKE 'https://%supabase.co/%' AND json_extract(data, '$._cf') IS NULL").first()).n;
        return jsonResponse({ coachSet: !!(await env.SITE_DATA.get("bm:coachpw")), kioskSet: !!(await env.SITE_DATA.get("bm:kioskkey")), photosToCopy: left, counts: { players: await t("players"), games: await t("games"), attendance: await t("attendance"), past_points: await t("past_points"), session_rsvps: await t("session_rsvps"), tournament_interest: await t("tournament_interest") } }, 200, corsHeaders);
      }
      if ((path === "/api/admin/badminton/coach-password" || path === "/api/admin/badminton/kiosk-key") && request.method === "PUT") {
        let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
        const v = String(b.value || "").trim();
        if (v.length < 6 || v.length > 60) return jsonResponse({ error: "Use 6–60 characters" }, 400, corsHeaders);
        if (path.endsWith("coach-password")) await env.SITE_DATA.put("bm:coachpw", await sha256Hex("bmcoach:" + v)); else await env.SITE_DATA.put("bm:kioskkey", await sha256Hex("bmkiosk:" + v));
        return jsonResponse({ ok: true }, 200, corsHeaders);
      }
      if (path === "/api/admin/badminton/match-report" && request.method === "GET") {
        const players = await bmLoadRows(env, "players"), users = await listAllUsers(env), games = await bmLoadRows(env, "games");
        const label = (r) => r.row.full_name || r.row.name || r.id;
        const gameCount = new Map(); for (const g of games) { const seen = new Set(); for (const f of ["winners", "losers"]) { let arr = Array.isArray(g.row[f]) ? g.row[f] : (() => { try { return JSON.parse(g.row[f]); } catch { return []; } })(); for (const v of arr || []) { const pl = players.find((q) => [q.row.id, q.row.name, q.row.nickname, q.row.full_name].filter(Boolean).map(String).includes(String(v))); if (pl && !seen.has(pl.id)) { seen.add(pl.id); gameCount.set(pl.id, (gameCount.get(pl.id) || 0) + 1); } } } }
        const linkedUids = new Set(players.filter((r) => r.uid).map((r) => r.uid));
        const out = [];
        for (const r of players.filter((x) => !x.uid)) {
          const ph = r.row.phone || r.row.username;
          const cands = users.map((u) => ({ userId: u.id, name: u.name, username: u.username, score: bmScore(label(r), u.name, ph, u.phone), taken: linkedUids.has(u.id) })).filter((c) => c.score >= 0.3).sort((a, b) => b.score - a.score).slice(0, 5);
          const dups = players.filter((o) => o.id !== r.id && bmScore(label(r), label(o)) >= 0.9).map((o) => ({ id: o.id, label: label(o), games: gameCount.get(o.id) || 0, linked: !!o.uid })).slice(0, 4);
          out.push({ id: r.id, label: label(r), level: r.row.level || null, games: gameCount.get(r.id) || 0, hasPhone: bmDigits(ph).length >= 7, cands, dups });
        }
        out.sort((a, b) => a.label.localeCompare(b.label));
        return jsonResponse({ unlinked: out, linked: players.length - out.length, total: players.length, users: users.slice(0, 2000).map((u) => ({ id: u.id, name: u.name, username: u.username })) }, 200, corsHeaders);
      }
      if (path === "/api/admin/badminton/link" && request.method === "POST") {
        let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
        const acts = (Array.isArray(b.actions) ? b.actions : []).slice(0, 120), result = { linked: 0, created: [], merged: 0, archived: 0, errors: [] };
        const clubMembers = async (uid) => { const club = (await readClubRoster(env)).find((c) => c.id === BM_BADMINTON_CLUB); if (club) { const ids = await readClubMemberIds(env, club.id); if (!ids.includes(uid)) await writeClubMemberIds(env, club.id, [...ids, uid]); } };
        for (const a of acts) {
          try {
            const pr = await env.DB.prepare("SELECT id, uid, data FROM bm_players WHERE id = ?").bind(String(a.playerId || "")).first(); if (!pr) { result.errors.push("Player not found"); continue; }
            const d = JSON.parse(pr.data), nm = d.full_name || d.name || "Player";
            if (a.action === "link") {
              const user = await readUser(env, String(a.userId || "")); if (!user) { result.errors.push(nm + ": that 4DS account no longer exists"); continue; }
              const other = await env.DB.prepare("SELECT id FROM bm_players WHERE uid = ? AND id != ?").bind(user.id, pr.id).first();
              if (other) { await bmMerge(env, other.id, pr.id); result.merged++; await clubMembers(user.id); continue; } // that account already has a player: they're the same person
              await env.DB.prepare("UPDATE bm_players SET uid = ? WHERE id = ?").bind(user.id, pr.id).run();
              const ph = sanitizePhone(d.phone || d.username); if (ph && !user.phone) { user.phone = ph; await writeUser(env, user); } // so they can log in by phone too
              await clubMembers(user.id); result.linked++;
            } else if (a.action === "create") {
              const name = sanitizePersonName(nm); if (!name) { result.errors.push("A name is missing"); continue; }
              const username = await generateUniqueUsername(env, name), pin = String(1000 + Math.floor(Math.random() * 9000));
              const user = { id: crypto.randomUUID(), name, username, pinHash: await sha256Hex(pin), photo: null, createdAt: Date.now(), mustChangePin: true };
              const ph = sanitizePhone(d.phone || d.username); if (ph) user.phone = ph;
              await writeUser(env, user); await reserveUsername(env, username, user.id);
              await env.DB.prepare("UPDATE bm_players SET uid = ? WHERE id = ?").bind(user.id, pr.id).run(); await clubMembers(user.id); _phoneMap = { at: 0, map: null };
              result.created.push({ name, username, pin, phone: ph || "" });
            } else if (a.action === "merge") {
              if (await bmMerge(env, String(a.into || ""), pr.id)) result.merged++; else result.errors.push(nm + ": couldn't merge");
            } else if (a.action === "archive") {
              d.active = false; await env.DB.prepare("UPDATE bm_players SET data = ? WHERE id = ?").bind(JSON.stringify(d), pr.id).run(); result.archived++;
            }
          } catch (e) { result.errors.push(String(e && e.message || e).slice(0, 120)); }
        }
        return jsonResponse({ ok: true, ...result }, 200, corsHeaders);
      }
      if (path === "/api/admin/badminton/copy-photos" && request.method === "POST") { // copies ONE profile photo per call from the old Supabase storage into 4DS (small CPU budget per request); the client loops until none are left
        try {
          const row = await env.DB.prepare("SELECT id, data FROM bm_players WHERE json_extract(data, '$.avatar_url') LIKE 'https://%supabase.co/%' AND json_extract(data, '$._cf') IS NULL LIMIT 1").first();
          let copied = 0, failed = 0, why = "";
          if (row) {
            const d = JSON.parse(row.data), m = String(d.avatar_url || "").match(/^https:\/\/[a-z0-9]+\.supabase\.co\/storage\/v1\/object\/public\/profile-avatars\/(.+)$/);
            try {
              if (!m) throw new Error("not a supabase url");
              const resp = await fetch(d.avatar_url); if (!resp.ok) throw new Error("fetch " + resp.status);
              const buf = new Uint8Array(await resp.arrayBuffer()); if (buf.length > 1500000) throw new Error("too big");
              let bin = ""; for (let k = 0; k < buf.length; k += 32768) bin += String.fromCharCode.apply(null, buf.subarray(k, k + 32768));
              const path2 = decodeURIComponent(m[1]).replace(/[^\w./@-]/g, "_");
              await env.DB.prepare("INSERT OR REPLACE INTO bm_files (path, ctype, b64, at) VALUES (?, ?, ?, ?)").bind(path2, resp.headers.get("content-type") || "image/jpeg", btoa(bin), Date.now()).run();
              d.avatar_url = "/storage/v1/object/public/profile-avatars/" + path2; copied = 1;
            } catch (e) { d._cf = true; failed = 1; why = String(e && e.message || e).slice(0, 80); } // keep the old link (so nothing is lost) but don't retry it forever
            await env.DB.prepare("UPDATE bm_players SET data = ? WHERE id = ?").bind(JSON.stringify(d), row.id).run();
          }
          const left = (await env.DB.prepare("SELECT COUNT(*) AS n FROM bm_players WHERE json_extract(data, '$.avatar_url') LIKE 'https://%supabase.co/%' AND json_extract(data, '$._cf') IS NULL").first()).n;
          return jsonResponse({ ok: true, copied, failed, why, left }, 200, corsHeaders);
        } catch (e) { return jsonResponse({ error: "Photo copy hit a snag: " + String(e && e.message || e).slice(0, 120) }, 500, corsHeaders); }
      }
      if (path.startsWith("/api/bm/")) {
        const memberId = await memberIdFromRequest();
        const meUser = memberId ? await readUser(env, memberId) : null;
        const coachTok = request.headers.get("X-BM-Coach") || "";
        const kioskKey = request.headers.get("X-Kiosk-Key") || "";
        let role = "anon";
        if (await isValidSession(getSessionToken(request))) role = "owner";
        else if (await bmLeadIsCoach(env, request)) role = "coach";
        else if (coachTok && (await env.SITE_DATA.get(`bmcoach:${coachTok}`))) role = "coach";
        else if (meUser) role = "member";
        else if (await bmKioskOk(env, kioskKey)) role = "kiosk";
        const staff = role === "owner" || role === "coach";
        if (path === "/api/bm/session" && request.method === "POST") {
          if (role === "owner") return jsonResponse({ session: { user: { id: BM_OWNER_ID, email: "owner" }, access_token: "owner" } }, 200, corsHeaders);
          if (role === "coach") return jsonResponse({ session: { user: { id: "coach", email: BM_COACH_EMAIL }, access_token: coachTok || "lead" } }, 200, corsHeaders);
          return jsonResponse({ session: null }, 200, corsHeaders);
        }
        if (path === "/api/bm/auth" && request.method === "POST") {
          if (!ideaRateOk(request.headers.get("CF-Connecting-IP") || "x")) return bmErr("Too many tries — wait a minute", 429);
          let b; try { b = await request.json(); } catch { return bmErr("Invalid request"); }
          const email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "");
          if (email === BM_COACH_EMAIL) { // the "Public admin" (the coach): today's games & attendance only
            const h = await env.SITE_DATA.get("bm:coachpw");
            if (!h || h !== await sha256Hex("bmcoach:" + pw)) return bmErr("Invalid login credentials", 401);
            const tok = crypto.randomUUID() + crypto.randomUUID();
            await env.SITE_DATA.put(`bmcoach:${tok}`, "1", { expirationTtl: 43200 });
            return jsonResponse({ session: { user: { id: "coach", email: BM_COACH_EMAIL }, access_token: tok } }, 200, corsHeaders);
          }
          if (!env.ADMIN_PASSWORD || pw !== env.ADMIN_PASSWORD) return bmErr("Invalid login credentials", 401); // "Owner admin" = the 4DS main admin password
          const tok = await createSession(), headers = new Headers({ "Content-Type": "application/json", ...corsHeaders });
          headers.set("Set-Cookie", setSessionCookie(tok));
          return new Response(JSON.stringify({ session: { user: { id: BM_OWNER_ID, email: "owner" }, access_token: "owner" } }), { status: 200, headers });
        }
        if (path === "/api/bm/logout" && request.method === "POST") { if (coachTok) await env.SITE_DATA.delete(`bmcoach:${coachTok}`).catch(() => {}); return jsonResponse({ ok: true }, 200, corsHeaders); }
        if (path === "/api/bm/notify" && request.method === "POST") {
          if (!ideaRateOk(request.headers.get("CF-Connecting-IP") || "x")) return bmErr("Slow down", 429);
          let b; try { b = await request.json(); } catch { return bmErr("Invalid request"); }
          const f = b.fields && typeof b.fields === "object" ? b.fields : {};
          sendAdminEmail(env, ctx, String(b.subject || "Badminton").slice(0, 120), `<p style="font-family:Arial,sans-serif">${Object.entries(f).slice(0, 12).map(([k, v]) => `<strong>${escapeHtml(String(k).slice(0, 30))}:</strong> ${escapeHtml(String(v).slice(0, 200))}`).join("<br>")}</p>`);
          return jsonResponse({ ok: true }, 200, corsHeaders);
        }
        if (path === "/api/bm/upload" && request.method === "POST") {
          if (role === "anon") return bmErr("Please log in first", 401);
          const fp = String(url.searchParams.get("path") || "");
          if (!/^self\/[\w.@-]{1,120}$/.test(fp)) return bmErr("Bad file name");
          const ctype = (request.headers.get("Content-Type") || "").split(";")[0].trim();
          if (!["image/jpeg", "image/png", "image/webp", "image/gif"].includes(ctype)) return bmErr("Photos only (JPG, PNG, WebP or GIF)");
          const buf = new Uint8Array(await request.arrayBuffer());
          if (!buf.length || buf.length > 2500000) return bmErr("That photo is too big");
          let bin = ""; for (let i = 0; i < buf.length; i += 8192) bin += String.fromCharCode(...buf.subarray(i, i + 8192));
          await env.DB.prepare("INSERT OR REPLACE INTO bm_files (path, ctype, b64, at) VALUES (?, ?, ?, ?)").bind(fp, ctype, btoa(bin), Date.now()).run();
          return jsonResponse({ data: { path: fp }, error: null }, 200, corsHeaders);
        }
        // ---- generic table access (a tiny PostgREST): the old row-level rules, re-created ----
        if (path === "/api/bm/q" && request.method === "POST") {
          let b; try { b = await request.json(); } catch { return bmErr("Invalid request"); }
          const key = String(b.table || ""); if (!BM_TBL[key]) return bmErr("Unknown table", 404);
          const op = String(b.op || "select"), today = bmToronto();
          const filters = Array.isArray(b.filters) ? b.filters : [];
          const cmp = (v, f) => { const a = v == null ? "" : String(v), x = f.val == null ? "" : String(f.val); switch (f.op) { case "eq": return a === x; case "neq": return a !== x; case "in": return (Array.isArray(f.val) ? f.val : []).map(String).includes(a); case "gt": return a > x; case "gte": return a >= x; case "lt": return a < x; case "lte": return a <= x; default: return false; } };
          const match = (row) => filters.every((f) => cmp(row[f.col], f));
          const rowsAll = await bmLoadRows(env, key, op !== "select");
          const isToday = (row) => { const d = key === "games" ? (row.played_at ? bmToronto(new Date(row.played_at)) : "") : String(row.session_date || ""); return d === today; };
          const canWrite = (action, row) => { // action: insert | update | delete
            if (role === "owner") return true;
            if (role !== "coach") return false;
            if (action === "delete") return false;
            if (key === "players") return true;
            if (key === "games" || key === "attendance") return isToday(row);
            return false;
          };
          if (op === "select") {
            // The leaderboard is PUBLIC: anyone can read players (first names / nicknames only, no photos), games, attendance and points. RSVPs and tournament interest need a login.
            if (role === "anon" && (key === "session_rsvps" || key === "tournament_interest")) return jsonResponse({ data: [], error: null }, 200, corsHeaders);
            // Public view: "Aya T." style names (first name + last initial); games are re-labelled the same way so the standings still line up.
            const pubAbbr = (d) => { const parts = String(d.full_name || d.name || "Player").trim().split(/\s+/); return parts.length > 1 ? `${parts[0]} ${parts[parts.length - 1][0].toUpperCase()}.` : parts[0]; };
            const pubNames = new Map(); if (role === "anon" && (key === "games" || key === "players")) for (const pr of (key === "players" ? rowsAll : await bmLoadRows(env, "players"))) for (const idv of [pr.row.name, pr.row.nickname, pr.row.full_name]) if (idv) pubNames.set(String(idv), pubAbbr(pr.row));
            let out = rowsAll.filter((r) => match(r.row)).map((r) => {
              const x = { ...r.row };
              if (key === "players") {
                delete x.pin; if (!staff && !(memberId && r.uid === memberId)) { delete x.phone; x.username = "x:" + r.id; }
                if (role === "anon") { delete x.nickname; x.full_name = x.name = pubAbbr(r.row); if (!String(x.avatar_url || "").startsWith("emoji:")) x.avatar_url = ""; }
              }
              if (role === "anon" && key === "games") { for (const f of ["winners", "losers"]) { const arr = Array.isArray(x[f]) ? x[f] : (() => { try { const j = JSON.parse(x[f]); return Array.isArray(j) ? j : null; } catch { return null; } })(); if (arr) x[f] = arr.map((v) => pubNames.get(String(v)) || v); } }
              if (key === "session_rsvps" || key === "tournament_interest") { if (!staff) { const own = x.username && meUser && bmDigits(meUser.phone) === bmDigits(x.username); if (!own) x.username = "x:" + (x.player_id || ""); } }
              return x;
            });
            for (const o of (Array.isArray(b.order) ? b.order : []).slice().reverse()) out.sort((p, q) => { const a = p[o.col], c = q[o.col]; const r = a == null ? (c == null ? 0 : -1) : c == null ? 1 : (typeof a === "number" && typeof c === "number" ? a - c : String(a).localeCompare(String(c))); return o.asc === false ? -r : r; });
            if (b.limit) out = out.slice(0, Math.min(5000, Number(b.limit) || 5000));
            if (b.single || b.maybe) { if (b.single && out.length !== 1) return jsonResponse({ data: null, error: { message: "JSON object requested, multiple (or no) rows returned" } }, 200, corsHeaders); return jsonResponse({ data: out[0] || null, error: null }, 200, corsHeaders); }
            return jsonResponse({ data: out, error: null }, 200, corsHeaders);
          }
          const stmts = []; let result = [];
          if (op === "insert" || op === "upsert") {
            const list = (Array.isArray(b.payload) ? b.payload : [b.payload]).filter((x) => x && typeof x === "object").slice(0, 500);
            const conflict = op === "upsert" ? String(b.onConflict || "").split(",").map((x) => x.trim()).filter(Boolean) : [];
            for (const raw of list) {
              const row = { ...raw }; delete row.pin;
              const existing = conflict.length ? rowsAll.find((r) => conflict.every((c) => String(r.row[c]) === String(row[c]))) : null;
              if (existing) { const merged = { ...existing.row, ...row }; if (!canWrite("update", merged) || !canWrite("update", existing.row)) return bmErr("Not allowed (public admin can only change today)", 403); stmts.push(bmSaveStmt(env, key, existing.id, merged, existing.uid)); result.push(merged); continue; }
              if (!canWrite("insert", row)) return bmErr(role === "anon" ? "Please log in" : "Not allowed (public admin can only add today's games and attendance)", 403);
              if (key === "games") { if (!row.played_at) row.played_at = new Date().toISOString(); row.week_id = row.week_id || bmWeekIdOf(bmToronto(new Date(row.played_at))); }
              if (key === "players") { row.active = row.active !== false; row.date_joined = row.date_joined || today; }
              row.id = row.id || (key === "attendance" ? `${row.player_id}:${row.session_date}` : crypto.randomUUID());
              stmts.push(bmSaveStmt(env, key, String(row.id), row, null)); result.push(row);
            }
          } else if (op === "update") {
            const patch = { ...(b.payload || {}) }; delete patch.pin; delete patch.id;
            for (const r of rowsAll.filter((x) => match(x.row))) { const merged = { ...r.row, ...patch }; if (!canWrite("update", r.row) || !canWrite("update", merged)) return bmErr("Not allowed (public admin can only change today)", 403); stmts.push(bmSaveStmt(env, key, r.id, merged, r.uid)); result.push(merged); }
          } else if (op === "delete") {
            if (role !== "owner") return bmErr("Owner admin only", 403);
            for (const r of rowsAll.filter((x) => match(x.row))) { stmts.push(env.DB.prepare(`DELETE FROM ${BM_TBL[key]} WHERE id = ?`).bind(r.id)); result.push(r.row); }
          } else return bmErr("Unsupported");
          for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
          if (stmts.length) bmCacheClear();
          return jsonResponse({ data: b.returning ? result : null, error: null }, 200, corsHeaders);
        }
        // ---- the old database functions ----
        if (path === "/api/bm/rpc" && request.method === "POST") {
          let b; try { b = await request.json(); } catch { return bmErr("Invalid request"); }
          const fn = String(b.name || ""), a = b.args || {}, today = bmToronto();
          const needMember = () => meUser ? null : bmErr("Please log in again", 401);
          const asRow = (pl) => ({ id: pl.id, name: pl.data.name, full_name: pl.data.full_name, username: pl.data.username, level: pl.data.level ?? null, avatar_url: pl.data.avatar_url || null });
          const setPlayer = async (pl, patch) => { const d = { ...pl.data, ...patch }; await env.DB.prepare("UPDATE bm_players SET data = ? WHERE id = ?").bind(JSON.stringify(d), pl.id).run(); return d; };
          if (fn === "login_player" || fn === "whoami") { const e = needMember(); if (e) return e; return jsonResponse({ data: [asRow(await bmPlayerFor(env, meUser))], error: null }, 200, corsHeaders); }
          if (fn === "signup_player") {
            const full = cleanCalText(a.p_full_name, 60), pin = String(a.p_pin || "").trim(), digits = bmDigits(a.p_phone), level = Math.round(Number(a.p_level));
            if (!full || !/^\d{4}$/.test(pin) || digits.length < 7 || !(level >= 1 && level <= 5)) return bmErr("Please fill in your name, phone, level and a 4-digit PIN");
            const taken = await usernameForPhone(env, digits, ctx); if (taken) return bmErr("That phone number is already signed up");
            const made = await createMemberFromForm(env, ctx, request.headers.get("CF-Connecting-IP") || "unknown", { name: full, pin, phone: a.p_phone });
            if (made.error) return bmErr(made.error, made.status || 400);
            _phoneMap = { at: 0, map: null };
            const club = (await readClubRoster(env)).find((c) => c.id === BM_BADMINTON_CLUB);
            if (club) { const ids = await readClubMemberIds(env, club.id); if (!ids.includes(made.user.id)) await writeClubMemberIds(env, club.id, [...ids, made.user.id]); }
            const pl = await bmPlayerFor(env, made.user); await setPlayer(pl, { level });
            return jsonResponse({ data: { token: made.token }, error: null }, 200, corsHeaders);
          }
          if (fn === "set_my_rsvp" || fn === "set_tournament_interest") {
            const e = needMember(); if (e) return e; const pl = await bmPlayerFor(env, meUser);
            if (fn === "set_my_rsvp") {
              const week = Math.round(Number(a.p_week)), status = ["yes", "maybe", "no"].includes(a.p_status) ? a.p_status : "";
              if (!(week >= 1 && week <= 60) || !status) return bmErr("Pick Yes, Maybe or No");
              await env.DB.prepare("INSERT OR REPLACE INTO bm_rsvps (id, day, data) VALUES (?, '', ?)").bind(`${pl.id}:${week}`, JSON.stringify({ username: pl.data.username, player_id: pl.id, week_number: week, status })).run();
              await env.DB.prepare("DELETE FROM bm_rsvps WHERE id != ? AND json_extract(data, '$.username') = ? AND json_extract(data, '$.week_number') = ?").bind(`${pl.id}:${week}`, pl.data.username || "~", week).run();
            } else {
              await env.DB.prepare("INSERT OR REPLACE INTO bm_interest (id, day, data) VALUES (?, '', ?)").bind(pl.id, JSON.stringify({ username: pl.data.username, player_id: pl.id, interested: !!a.p_interested })).run();
              await env.DB.prepare("DELETE FROM bm_interest WHERE id != ? AND json_extract(data, '$.username') = ?").bind(pl.id, pl.data.username || "~").run();
            }
            return jsonResponse({ data: null, error: null }, 200, corsHeaders);
          }
          if (fn === "set_player_avatar") {
            const e = needMember(); if (e) return e; const pl = await bmPlayerFor(env, meUser), u = String(a.p_avatar_url || "");
            const m = u.match(/\/storage\/v1\/object\/public\/profile-avatars\/(self\/[\w.@-]+)$/); if (!m) return bmErr("That picture isn't allowed");
            await setPlayer(pl, { avatar_url: "/storage/v1/object/public/profile-avatars/" + m[1] }); return jsonResponse({ data: null, error: null }, 200, corsHeaders);
          }
          if (fn === "update_my_profile") {
            const e = needMember(); if (e) return e; const pl = await bmPlayerFor(env, meUser), patch = {};
            const user = { ...meUser };
            if (a.p_new_full_name) { const n = cleanCalText(a.p_new_full_name, 60); if (!n) return bmErr("Name is required"); patch.full_name = n; patch.name = firstNameOnly(n); user.name = n; }
            if (a.p_new_phone) { const d = bmDigits(a.p_new_phone); if (d.length < 7) return bmErr("Enter a valid phone number"); const other = await usernameForPhone(env, d, ctx); if (other && other !== meUser.username) return bmErr("That phone number is already used"); patch.phone = d; patch.username = d; user.phone = sanitizePhone(a.p_new_phone) || user.phone; _phoneMap = { at: 0, map: null }; }
            if (a.p_new_pin) { if (!/^\d{4}$/.test(String(a.p_new_pin))) return bmErr("New PIN must be exactly 4 digits"); user.pinHash = await sha256Hex(String(a.p_new_pin)); }
            await writeUser(env, user); await setPlayer(pl, patch);
            return jsonResponse({ data: null, error: null }, 200, corsHeaders);
          }
          if (fn === "admin_delete_player") {
            if (role !== "owner") return bmErr("Owner admin only", 403);
            const id = String(a.p_player_id || ""); if (!id) return bmErr("No player");
            await env.DB.batch([env.DB.prepare("DELETE FROM bm_players WHERE id = ?").bind(id), env.DB.prepare("DELETE FROM bm_attendance WHERE json_extract(data, '$.player_id') = ?").bind(id), env.DB.prepare("DELETE FROM bm_past WHERE json_extract(data, '$.player_id') = ?").bind(id), env.DB.prepare("DELETE FROM bm_rsvps WHERE json_extract(data, '$.player_id') = ?").bind(id), env.DB.prepare("DELETE FROM bm_interest WHERE json_extract(data, '$.player_id') = ?").bind(id)]);
            return jsonResponse({ data: null, error: null }, 200, corsHeaders);
          }
          if (fn.startsWith("kiosk_")) {
            if (!(await bmKioskOk(env, String(a.p_key || "")))) return bmErr("This iPad is not set up as the kiosk", 403);
            if (fn === "kiosk_ping") return jsonResponse({ data: true, error: null }, 200, corsHeaders);
            const playerRow = async (id) => { const r = await env.DB.prepare("SELECT id, data FROM bm_players WHERE id = ?").bind(String(id)).first(); return r ? { id: r.id, data: JSON.parse(r.data) } : null; };
            if (fn === "kiosk_check_in") {
              const pl = await playerRow(a.p_player_id); if (!pl) return bmErr("Player not found");
              const day = String(a.p_date || ""); if (day !== today) return bmErr("The kiosk can only check people in for today");
              await env.DB.prepare("INSERT OR REPLACE INTO bm_attendance (id, day, data) VALUES (?, ?, ?)").bind(`${pl.id}:${day}`, day, JSON.stringify({ id: `${pl.id}:${day}`, player_id: pl.id, session_date: day, present: !!a.p_present })).run();
              await env.DB.prepare("DELETE FROM bm_attendance WHERE id != ? AND json_extract(data, '$.player_id') = ? AND json_extract(data, '$.session_date') = ?").bind(`${pl.id}:${day}`, pl.id, day).run();
              return jsonResponse({ data: null, error: null }, 200, corsHeaders);
            }
            if (fn === "kiosk_reactivate") {
              const pl = await playerRow(a.p_player_id); if (!pl) return bmErr("Player not found");
              await setPlayer(pl, { active: true }); return jsonResponse({ data: null, error: null }, 200, corsHeaders);
            }
            if (fn === "kiosk_record_game") {
              const w = (Array.isArray(a.p_winner_ids) ? a.p_winner_ids : []).map(String), l = (Array.isArray(a.p_loser_ids) ? a.p_loser_ids : []).map(String), ws = Math.round(Number(a.p_winner_score)), ls = Math.round(Number(a.p_loser_score));
              if (!((w.length === 1 && l.length === 1) || (w.length === 2 && l.length === 2)) || new Set([...w, ...l]).size !== w.length + l.length) return bmErr("Pick a winner and a loser (1v1 or 2v2)");
              if (!Number.isFinite(ws) || !Number.isFinite(ls) || ws <= ls || ws < 11 || ws > 60 || ls < 0) return bmErr("The winning score must be at least 11 and higher than the losing score");
              for (const id of [...w, ...l]) if (!(await playerRow(id))) return bmErr("Player not found");
              if (String(a.p_date || "") !== today) return bmErr("The kiosk can only record today's games");
              const game = { id: crypto.randomUUID(), winners: w, losers: l, played_at: new Date().toISOString(), week_id: bmWeekIdOf(today), winner_score: ws, loser_score: ls };
              await env.DB.prepare("INSERT INTO bm_games (id, day, data) VALUES (?, ?, ?)").bind(game.id, today, JSON.stringify(game)).run();
              return jsonResponse({ data: game.id, error: null }, 200, corsHeaders);
            }
            if (fn === "kiosk_undo_game") {
              const g = await env.DB.prepare("SELECT id, data FROM bm_games WHERE id = ?").bind(String(a.p_game_id || "")).first(); if (!g) return jsonResponse({ data: false, error: null }, 200, corsHeaders);
              const d = JSON.parse(g.data); if (!d.played_at || Date.now() - new Date(d.played_at).getTime() > 30 * 60000) return jsonResponse({ data: false, error: null }, 200, corsHeaders); // only a game just recorded
              await env.DB.prepare("DELETE FROM bm_games WHERE id = ?").bind(g.id).run(); return jsonResponse({ data: true, error: null }, 200, corsHeaders);
            }
            if (fn === "kiosk_set_avatar") {
              const pl = await playerRow(a.p_player_id); if (!pl) return bmErr("Player not found");
              const av = String(a.p_avatar || "").replace(/^https?:\/\/[^/]+(?=\/storage\/)/, ""), ok = BM_HEARTS.map((h) => "emoji:" + h).includes(av) || av.startsWith(`/storage/v1/object/public/profile-avatars/self/kiosk-${pl.id}-`);
              if (!ok) return bmErr("That picture is not allowed");
              await setPlayer(pl, { avatar_url: av }); return jsonResponse({ data: null, error: null }, 200, corsHeaders);
            }
          }
          return bmErr("Unknown function " + fn, 404);
        }
        return bmErr("Not found", 404);
      }
    }
    // ---- Club leads: a scoped admin that can only manage the clubs they were assigned ----
    const getLeadToken = (req) => {
      const m = (req.headers.get("Cookie") || "").match(/(?:^|;\s*)leadsession=([^;]+)/);
      return m ? m[1] : null;
    };
    const getLead = async (req) => {
      const t = getLeadToken(req);
      if (!t) return null;
      let sess;
      try { sess = JSON.parse((await env.SITE_DATA.get(`leadsession:${t}`)) || "null"); } catch { return null; }
      if (!sess || (sess.expiresAt && Date.now() > sess.expiresAt)) return null;
      let rec;
      try { rec = JSON.parse((await env.SITE_DATA.get(`clublead:${sess.username}`)) || "null"); } catch { return null; }
      if (!rec) return null;
      return { username: rec.username, name: rec.name, clubs: Array.isArray(rec.clubs) ? rec.clubs : [], mustChange: !!rec.mustChange };
    };
    const leadCookie = (t, maxAge) => `leadsession=${t}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

    if (path === "/api/clubadmin/login" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const username = String(body.username || "").trim().toLowerCase().slice(0, 40);
      const password = String(body.password || "");
      const hourSlot = Math.floor(Date.now() / 3600000);
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const keys = [`loginrate:leadip:${ip}:${hourSlot}`, `loginrate:lead:${username}:${hourSlot}`];
      const counts = await Promise.all(keys.map((k) => env.SITE_DATA.get(k)));
      if (counts.some((c) => Number(c || 0) >= 10)) return jsonResponse({ error: "Too many attempts — try again in an hour" }, 429, corsHeaders);
      await Promise.all(keys.map((k, i) => env.SITE_DATA.put(k, String(Number(counts[i] || 0) + 1), { expirationTtl: 3700 })));
      let rec = null;
      try { rec = JSON.parse((await env.SITE_DATA.get(`clublead:${username}`)) || "null"); } catch {}
      if (!rec || !username || rec.passHash !== await sha256Hex(`${rec.salt}:${password}`)) return jsonResponse({ error: "Incorrect username or password" }, 401, corsHeaders);
      const token = crypto.randomUUID();
      await env.SITE_DATA.put(`leadsession:${token}`, JSON.stringify({ username, expiresAt: Date.now() + SESSION_TTL * 1000 }), { expirationTtl: SESSION_TTL });
      const headers = new Headers({ "Content-Type": "application/json", ...corsHeaders });
      headers.set("Set-Cookie", leadCookie(token, SESSION_TTL));
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (path === "/api/clubadmin/password" && request.method === "POST") {
      const lead = await getLead(request);
      if (!lead) return jsonResponse({ error: "Please log in again" }, 401, corsHeaders);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const next = String(body.password || "");
      if (next.length < 8) return jsonResponse({ error: "Use at least 8 characters" }, 400, corsHeaders);
      let rec;
      try { rec = JSON.parse((await env.SITE_DATA.get(`clublead:${lead.username}`)) || "null"); } catch { rec = null; }
      if (!rec) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      if (rec.passHash === await sha256Hex(`${rec.salt}:${next}`)) return jsonResponse({ error: "Pick a new password, different from the one you were given" }, 400, corsHeaders);
      rec.salt = crypto.randomUUID(); rec.passHash = await sha256Hex(`${rec.salt}:${next}`); rec.mustChange = false;
      await env.SITE_DATA.put(`clublead:${lead.username}`, JSON.stringify(rec));
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }

    if (path === "/api/clubadmin/logout" && request.method === "POST") {
      const t = getLeadToken(request);
      if (t) await env.SITE_DATA.delete(`leadsession:${t}`).catch(() => {});
      const headers = new Headers({ "Content-Type": "application/json", ...corsHeaders });
      headers.set("Set-Cookie", leadCookie("", 0));
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    if (path === "/api/admin/session" && request.method === "GET") {
      const loggedIn = await isValidSession(getSessionToken(request));
      const lead = await getLead(request);
      return jsonResponse({ loggedIn, lead }, 200, corsHeaders);
    }

    // A lead may only use these admin routes, and only for their own clubs. Anything else stays full-admin.
    let leadCtx = null;
    if (path.startsWith("/api/admin/") && !(await isValidSession(getSessionToken(request)))) {
      const lead = await getLead(request);
      if (lead) {
        const own = new Set(lead.clubs);
        const memberOf = async (clubId, userId) => (await readClubMemberIds(env, clubId)).includes(userId);
        const inAnyOwn = async (userId) => { for (const c of lead.clubs) if (await memberOf(c, userId)) return true; return false; };
        const seg = path.split("/").slice(3).map((x) => decodeURIComponent(x));
        const M = request.method;
        let ok = false;
        if (path === "/api/admin/club-members" && M === "GET") ok = true;
        else if (path === "/api/admin/users" && M === "GET") ok = true;
        else if (path === "/api/admin/idea-availability" && M === "GET") ok = true;
        else if (path === "/api/admin/avail-periods" && M === "GET") ok = true; // club admins can look back at earlier periods
        else if (path === "/api/admin/join-requests" && M === "GET") ok = true;
        else if (path === "/api/admin/calendar-event" && M === "POST") ok = true;
        else if (path === "/api/admin/wa-templates" && M === "GET") ok = true;
        else if (path === "/api/admin/reminders/last" && M === "GET") ok = true;
        else if ((path === "/api/admin/push/send" || path === "/api/admin/remind-availability") && M === "POST") {
          // Reminders go only to people in the clubs they lead; anyone else in the list is silently dropped.
          ok = true;
          let b = {};
          try { b = await request.clone().json(); } catch {}
          const mine = [];
          for (const id of (Array.isArray(b.userIds) ? b.userIds.map(String) : []).slice(0, 500)) if (await inAnyOwn(id)) mine.push(id);
          request = new Request(request.url, { method: "POST", headers: request.headers, body: JSON.stringify({ ...b, userIds: mine }) });
        }
        else if (seg[0] === "join-requests" && seg.length === 4 && M === "POST") ok = own.has(seg[1]);
        else if (seg[0] === "club-cal") ok = true; // ownership of the club is checked inside the handlers
        else if (seg[0] === "club-events" && own.has(seg[1]) && ((seg.length === 2 && (M === "GET" || M === "POST")) || (seg.length === 3 && M === "DELETE"))) ok = true;
        else if (seg[0] === "club-members" && own.has(seg[1])) {
          if (seg.length === 2 && M === "POST") ok = true;
          // A club admin can ADD people to their club and take someone OUT of their club — but never edit a profile (name, phone, PIN…) or reset a PIN.
          else if (seg.length === 3 && M === "DELETE") ok = await memberOf(seg[1], seg[2]);
        }
        // They can open the full profile of anyone in their clubs AND of anyone who has asked to join / is on standby for one of their clubs.
        else if (seg[0] === "users" && seg.length === 3 && seg[2] === "profile" && M === "GET") {
          ok = await inAnyOwn(seg[1]);
          if (!ok) {
            for (const c of lead.clubs) if (await env.SITE_DATA.get(joinReqKey(c, seg[1]))) { ok = true; break; }
            if (!ok) { const tu = await readUser(env, seg[1]); ok = !!(tu && Array.isArray(tu.waitlist) && tu.waitlist.some((c) => own.has(c))); }
          }
        }
        else if (seg[0] === "users" && seg.length === 3 && seg[2] === "archive" && M === "PUT") ok = await inAnyOwn(seg[1]);
        else if (seg[0] === "users" && seg.length === 3 && seg[2] === "reminded" && M === "POST") ok = await inAnyOwn(seg[1]);
        else if (seg[0] === "users" && seg.length === 3 && seg[2] === "clubs" && M === "PUT") {
          ok = await inAnyOwn(seg[1]);
          if (ok) {
            // They can only add/remove the clubs they lead; the person's other clubs are left exactly as they are.
            let b = {};
            try { b = await request.clone().json(); } catch {}
            const current = await allClubIdsContaining(env, seg[1]);
            const wanted = (Array.isArray(b.clubs) ? b.clubs.map(String) : []).filter((c) => own.has(c));
            const merged = [...new Set([...current.filter((c) => !own.has(c)), ...wanted])];
            request = new Request(request.url, { method: "PUT", headers: request.headers, body: JSON.stringify({ clubs: merged }) });
          }
        }
        if (!ok) return jsonResponse({ error: "Club leads can't do that" }, 403, corsHeaders);
        leadCtx = lead;
      }
    }

    // ---- Auth guard for editor and writes ----

    const requiresAuth = path === "/editor" || (path.startsWith("/api/data/") && request.method === "POST") || path.startsWith("/api/admin/club-members") || path.startsWith("/api/admin/join-requests") || path.startsWith("/api/admin/event-suggestions") || path.startsWith("/api/admin/resource-suggestions") || path.startsWith("/api/admin/club-events") || path.startsWith("/api/admin/club-cal") || path.startsWith("/api/admin/event-form") || path === "/api/admin/users" || path.startsWith("/api/admin/users/") || path.startsWith("/api/admin/import-phones") || path.startsWith("/api/admin/remind-availability") || path.startsWith("/api/admin/push") || path.startsWith("/api/admin/reminders") || path.startsWith("/api/admin/squad") || path.startsWith("/api/admin/calendar-event") || path.startsWith("/api/admin/resource") || path.startsWith("/api/admin/sitetext") || path.startsWith("/api/admin/club-ideas") || path.startsWith("/api/admin/idea-availability") || path.startsWith("/api/admin/reviews") || path.startsWith("/api/admin/app-config") || path.startsWith("/api/admin/clubs") || path.startsWith("/api/admin/club-leads") || path.startsWith("/api/admin/labels") || path.startsWith("/api/admin/avail-period") || path.startsWith("/api/admin/d1-") || path.startsWith("/api/admin/backup") || path.startsWith("/api/admin/wa-templates") || path.startsWith("/api/admin/email-preview");

    if (requiresAuth && !leadCtx) {
      const token = getSessionToken(request);
      const valid = await isValidSession(token);
      if (!valid) {
        if (path === "/editor") {
          const error = url.searchParams.get("error");
          const html = `<!DOCTYPE html>
<html>
<head>
  <title>4DASISTAS Editor — Login</title>
  <style>
    body { font-family: system-ui; max-width: 400px; margin: 80px auto; padding: 20px; text-align: center; }
    input { width: 100%; padding: 12px; margin: 10px 0; font-size: 16px; box-sizing: border-box; }
    button { width: 100%; padding: 12px; background: #373d3b; color: white; border: none; font-size: 16px; cursor: pointer; }
    .error { color: #c00; }
  </style>
</head>
<body>
  <h1>4DASISTAS Editor</h1>
  ${error === '1' ? '<p class="error">Invalid password. Please try again.</p>' : ''}${error === '2' ? '<p class="error">Server misconfigured: the ADMIN_PASSWORD secret is not set, so nobody can log in. Set it with <code>npx wrangler secret put ADMIN_PASSWORD</code>.</p>' : ''}
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="Admin password" required autofocus>
    <button type="submit">Login</button>
  </form>
  <p style="margin-top: 20px; font-size: 12px; color: #666;">Enter the admin password to access the editor.</p>
</body>
</html>`;
          return new Response(html, {
            headers: { "Content-Type": "text/html", ...corsHeaders },
          });
        }
        return new Response("Unauthorized", { status: 401, headers: corsHeaders });
      }
    }

    // ---- API routes ----

    // The availability PERIOD: the fixed block of dates people fill in (and everyone sees, in member + admin views). Nothing outside it is offered
    // or assumed available. The MAIN admin opens the next one manually. Until one is saved, it defaults to Oct 8 – Oct 20, 2026.
    const readAvailPeriod = () => readAvailPeriodKV(env);
    const readAvailDoc = async () => { try { return JSON.parse((await env.SITE_DATA.get("availperiod")) || "null") || {}; } catch { return {}; } };
    const readPeriodHistory = async () => { try { const a = JSON.parse((await env.SITE_DATA.get("availperiods")) || "[]"); return Array.isArray(a) ? a : []; } catch { return []; } };
    if (path === "/api/avail-period" && request.method === "GET") {
      const cur = await readAvailPeriod(), doc = await readAvailDoc();
      const ann = doc.announce && doc.announce.start === cur.start && doc.announce.end === cur.end ? { id: doc.announce.id, text: doc.announce.text } : null;
      return jsonResponse({ ...cur, ...(doc.deadline ? { deadline: doc.deadline } : {}), ...(ann ? { announce: ann } : {}) }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    // Every period the admin has opened is kept, so an old one can be opened again to look at everyone's availability then.
    if (path === "/api/avail-periods" && request.method === "GET") return jsonResponse(await listAvailPeriods(env), 200, { ...corsHeaders, "Cache-Control": "no-store" });
    if (path === "/api/admin/avail-periods" && request.method === "GET") {
      const cur = await readAvailPeriod();
      const hist = (await listAvailPeriods(env)).periods;
      return jsonResponse({ current: cur, periods: hist }, 200, corsHeaders);
    }
    // Edit or delete a saved period (the CURRENT one can be edited — it changes the live period — but not deleted).
    if (path === "/api/admin/avail-periods" && (request.method === "PUT" || request.method === "DELETE")) {
      let body = {};
      if (request.method === "PUT") { try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); } }
      const start = String(body.start || url.searchParams.get("start") || ""), end = String(body.end || url.searchParams.get("end") || "");
      if (!isValidDateString(start) || !isValidDateString(end)) return jsonResponse({ error: "Unknown period" }, 400, corsHeaders);
      const cur = await readAvailPeriod(), isCur = cur.start === start && cur.end === end;
      let hist = (await listAvailPeriods(env)).periods;
      if (!hist.some((h) => h.start === start && h.end === end)) return jsonResponse({ error: "That period isn't in the list" }, 404, corsHeaders);
      let hidden = []; try { const a = JSON.parse((await env.SITE_DATA.get("availperiodsHidden")) || "[]"); if (Array.isArray(a)) hidden = a; } catch {}
      if (request.method === "DELETE") {
        if (isCur) return jsonResponse({ error: "That's the current period — set a different current period first, then delete this one" }, 400, corsHeaders);
        hist = hist.filter((h) => !(h.start === start && h.end === end));
        if (!hidden.includes(`${start}_${end}`)) hidden.push(`${start}_${end}`);
      } else {
        const ns = String(body.newStart || ""), ne = String(body.newEnd || "");
        if (!isValidDateString(ns) || !isValidDateString(ne) || ne < ns) return jsonResponse({ error: "Pick a start date and an end date after it" }, 400, corsHeaders);
        if ((Date.parse(ne + "T00:00:00Z") - Date.parse(ns + "T00:00:00Z")) / 86400000 > 45) return jsonResponse({ error: "Keep the period to 45 days or less" }, 400, corsHeaders);
        if ((ns !== start || ne !== end) && hist.some((h) => h.start === ns && h.end === ne)) return jsonResponse({ error: "A period with those dates already exists" }, 409, corsHeaders);
        hist = hist.map((h) => (h.start === start && h.end === end ? { ...h, start: ns, end: ne } : h));
        if (!hidden.includes(`${start}_${end}`) && (ns !== start || ne !== end)) hidden.push(`${start}_${end}`); // (hides the old dates if it was the built-in first period)
        hidden = hidden.filter((k) => k !== `${ns}_${ne}`);
        if (isCur) { const doc = await readAvailDoc(); await env.SITE_DATA.put("availperiod", JSON.stringify({ ...doc, start: ns, end: ne, at: Date.now() })); }
      }
      hist = hist.map((h) => ({ start: h.start, end: h.end, at: h.at || 0 }));
      hist.sort((a, b) => b.start.localeCompare(a.start));
      await env.SITE_DATA.put("availperiods", JSON.stringify(hist.slice(0, 40)));
      await env.SITE_DATA.put("availperiodsHidden", JSON.stringify(hidden.slice(0, 40)));
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    // Add an OLDER period to the saved list (it does not change the current one) so its availability can be viewed again.
    if (path === "/api/admin/avail-periods" && request.method === "POST") {
      let body; try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const start = String(body.start || ""), end = String(body.end || "");
      if (!isValidDateString(start) || !isValidDateString(end) || end < start) return jsonResponse({ error: "Pick a start date and an end date after it" }, 400, corsHeaders);
      const hist = await readPeriodHistory();
      if (!hist.some((h) => h.start === start && h.end === end)) hist.push({ start, end, at: Date.now() });
      hist.sort((a, b) => b.start.localeCompare(a.start));
      await env.SITE_DATA.put("availperiods", JSON.stringify(hist.slice(0, 40)));
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    if (path === "/api/admin/avail-period/announce" && request.method === "POST") {
      let body; try { body = await request.json(); } catch { body = {}; }
      const cur = await readAvailPeriod(), doc = await readAvailDoc();
      const text = String(body.message || "").replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f<>]/g, " ").trim().slice(0, 240);
      doc.announce = text ? { id: crypto.randomUUID(), text, start: cur.start, end: cur.end, at: Date.now() } : null;
      if (/^\d{4}-\d{2}-\d{2}$/.test(String(body.deadline || ""))) doc.deadline = String(body.deadline);
      await env.SITE_DATA.put("availperiod", JSON.stringify({ ...doc, start: cur.start, end: cur.end }));
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    if (path === "/api/admin/avail-period" && request.method === "PUT") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const start = String(body.start || ""), end = String(body.end || "");
      if (!isValidDateString(start) || !isValidDateString(end)) return jsonResponse({ error: "Pick a start and an end date" }, 400, corsHeaders);
      if (end < start) return jsonResponse({ error: "The end date can't be before the start date" }, 400, corsHeaders);
      if ((Date.parse(end + "T00:00:00Z") - Date.parse(start + "T00:00:00Z")) / 86400000 > 45) return jsonResponse({ error: "Keep the period to 45 days or less" }, 400, corsHeaders);
      const deadline = /^\d{4}-\d{2}-\d{2}$/.test(String(body.deadline || "")) ? String(body.deadline) : "";
      const prev = await readAvailPeriod();
      let hist = await readPeriodHistory();
      for (const per of [prev, { start, end }]) if (!hist.some((h) => h.start === per.start && h.end === per.end)) hist.unshift({ start: per.start, end: per.end, at: Date.now() });
      hist.sort((a, b) => b.start.localeCompare(a.start));
      await env.SITE_DATA.put("availperiods", JSON.stringify(hist.slice(0, 40)));
      await env.SITE_DATA.put("availperiod", JSON.stringify({ start, end, deadline, at: Date.now() }));
      return jsonResponse({ ok: true, start, end, deadline, changed: prev.start !== start || prev.end !== end }, 200, corsHeaders);
    }

    // Editable display names for resource categories and event genres (keys stay fixed; only the words people see change).
    const LABEL_KEYS = { resource: RESOURCE_CATEGORIES, event: ["sports", "activities", "functions", "trips", "mosqueprograms"] };
    if (path === "/api/labels" && request.method === "GET") {
      let o = {};
      try { o = JSON.parse((await env.SITE_DATA.get("labels")) || "{}") || {}; } catch {}
      return jsonResponse({ resource: o.resource || {}, event: o.event || {} }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }
    if (path === "/api/admin/labels" && request.method === "PUT") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const out = { resource: {}, event: {} };
      for (const group of ["resource", "event"]) {
        for (const key of LABEL_KEYS[group]) {
          const v = String((body[group] || {})[key] || "").replace(/[\x00-\x1f<>]/g, " ").trim().slice(0, 40);
          if (v) out[group][key] = v;
        }
      }
      await env.SITE_DATA.put("labels", JSON.stringify(out));
      return jsonResponse({ ok: true, ...out }, 200, corsHeaders);
    }

    // Admin only: create / list / edit / delete club-lead logins (a scoped admin for one or more clubs).
    if (path === "/api/admin/club-leads" && request.method === "GET") {
      const out = [];
      for (const k of (await env.SITE_DATA.list({ prefix: "clublead:" })).keys) {
        try { const r = JSON.parse(await env.SITE_DATA.get(k.name)); if (r) out.push({ username: r.username, name: r.name, clubs: r.clubs || [], createdAt: r.createdAt || 0 }); } catch {}
      }
      return jsonResponse({ leads: out }, 200, corsHeaders);
    }
    if (path === "/api/admin/club-leads" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const name = String(body.name || "").trim().slice(0, 60);
      const username = String(body.username || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 40);
      const password = String(body.password || "");
      const clubs = (Array.isArray(body.clubs) ? body.clubs : []).map(String);
      if (!name || !username) return jsonResponse({ error: "Name and username are required" }, 400, corsHeaders);
      if (password.length < 6) return jsonResponse({ error: "Password must be at least 6 characters" }, 400, corsHeaders);
      if (!clubs.length) return jsonResponse({ error: "Pick at least one club" }, 400, corsHeaders);
      if (await env.SITE_DATA.get(`clublead:${username}`)) return jsonResponse({ error: "That username is already taken" }, 409, corsHeaders);
      const salt = crypto.randomUUID();
      const rec = { username, name, clubs, salt, passHash: await sha256Hex(`${salt}:${password}`), createdAt: Date.now(), mustChange: true };
      await env.SITE_DATA.put(`clublead:${username}`, JSON.stringify(rec));
      return jsonResponse({ ok: true, username }, 201, corsHeaders);
    }
    const leadAdminMatch = path.match(/^\/api\/admin\/club-leads\/([^/]+)\/?$/);
    if (leadAdminMatch && (request.method === "PUT" || request.method === "DELETE")) {
      const username = decodeURIComponent(leadAdminMatch[1]).toLowerCase();
      let rec;
      try { rec = JSON.parse((await env.SITE_DATA.get(`clublead:${username}`)) || "null"); } catch { rec = null; }
      if (!rec) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      if (request.method === "DELETE") {
        await env.SITE_DATA.delete(`clublead:${username}`);
        return jsonResponse({ ok: true }, 200, corsHeaders);
      }
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (body.name !== undefined) rec.name = String(body.name).trim().slice(0, 60) || rec.name;
      if (Array.isArray(body.clubs)) { if (!body.clubs.length) return jsonResponse({ error: "Pick at least one club" }, 400, corsHeaders); rec.clubs = body.clubs.map(String); }
      if (body.password) {
        if (String(body.password).length < 6) return jsonResponse({ error: "Password must be at least 6 characters" }, 400, corsHeaders);
        rec.salt = crypto.randomUUID(); rec.passHash = await sha256Hex(`${rec.salt}:${body.password}`); rec.mustChange = true;
      }
      await env.SITE_DATA.put(`clublead:${username}`, JSON.stringify(rec));
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }

    // Admin: manage club members / reset PINs (session-cookie gated above)
    if (path === "/api/admin/club-members" && request.method === "GET") {
      const SEEN = await seenMap(env);
      const out = {};
      for (const clubId of await clubIdList(env)) {
        if (leadCtx && !leadCtx.clubs.includes(clubId)) continue;
        out[clubId] = (await resolveClubMembers(env, clubId)).map((u) => ({ ...publicUser(u), phone: u.phone || "", createdAt: u.createdAt || 0, ...seenOf(SEEN, u) })); // phone + activity: admin-only
      }
      return jsonResponse(out, 200, corsHeaders);
    }

    // ---- Admin: see everyone's general availability by name (the public /all endpoint above
    // already returns names to any signed-in member too - this is kept for a pre-login/guest-cookie
    // admin view) ----
    if (path === "/api/admin/event-suggestions" && request.method === "GET") {
      const list = await env.SITE_DATA.list({ prefix: "eventsug:" });
      const out = [];
      for (const k of list.keys) { try { out.push(JSON.parse(await env.SITE_DATA.get(k.name))); } catch {} }
      out.sort((a, b) => a.date.localeCompare(b.date));
      const withUrl = [];
      for (const x of out.filter(Boolean)) withUrl.push({ ...x, reviewUrl: await reviewUrlFor(env, "event", x.id) });
      return jsonResponse({ suggestions: withUrl }, 200, corsHeaders);
    }
    if (path === "/api/admin/resource-suggestions" && request.method === "GET") {
      const list = await env.SITE_DATA.list({ prefix: "ressug:" });
      const out = [];
      for (const k of list.keys) { try { out.push(JSON.parse(await env.SITE_DATA.get(k.name))); } catch {} }
      out.sort((a, b) => (a.at || 0) - (b.at || 0));
      const withUrl = [];
      for (const x of out.filter(Boolean)) withUrl.push({ ...x, reviewUrl: await reviewUrlFor(env, "resource", x.id) });
      return jsonResponse({ suggestions: withUrl }, 200, corsHeaders);
    }
    const adminResSugMatch = path.match(/^\/api\/admin\/resource-suggestions\/([^/]+)\/?$/);
    if (adminResSugMatch && request.method === "DELETE") {
      await env.SITE_DATA.delete(`ressug:${decodeURIComponent(adminResSugMatch[1])}`);
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    const adminSugMatch = path.match(/^\/api\/admin\/event-suggestions\/([^/]+)\/?$/);
    if (adminSugMatch && request.method === "DELETE") {
      await env.SITE_DATA.delete(`eventsug:${decodeURIComponent(adminSugMatch[1])}`);
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }

    if (path === "/api/admin/app-config" && (request.method === "GET" || request.method === "PUT")) {
      if (leadCtx) return jsonResponse({ error: "Main admin only" }, 403, corsHeaders);
      let c = {}; try { c = JSON.parse((await env.SITE_DATA.get("appconfig")) || "{}"); } catch {}
      if (request.method === "PUT") {
        let body; try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
        c.minBuild = Math.max(0, Math.round(Number(body.minBuild) || 0)); if (body.message !== undefined) c.message = String(body.message || "").slice(0, 200);
        await env.SITE_DATA.put("appconfig", JSON.stringify(c));
      }
      return jsonResponse({ minBuild: Number(c.minBuild) || 0, message: c.message || "" }, 200, corsHeaders);
    }
    if (path === "/api/admin/reviews" && request.method === "GET") {
      if (leadCtx) return jsonResponse({ error: "Main admin only" }, 403, corsHeaders);
      if (!env.DB) return jsonResponse({ reviews: [] }, 200, corsHeaders);
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS event_reviews (user_id TEXT NOT NULL, event_id TEXT NOT NULL, title TEXT, ev_date TEXT, rating INTEGER NOT NULL, comment TEXT, at INTEGER, PRIMARY KEY (user_id, event_id))").run();
      const rows = (await env.DB.prepare("SELECT user_id, event_id, title, ev_date, rating, comment, at FROM event_reviews ORDER BY at DESC LIMIT 300").all()).results || [];
      const out = [];
      for (const r of rows) { const u = await readUser(env, r.user_id); out.push({ title: r.title, date: r.ev_date, rating: r.rating, comment: r.comment, at: r.at, who: u ? `${u.name || ""} (@${u.username || ""})` : "a member" }); }
      return jsonResponse({ reviews: out }, 200, { ...corsHeaders, "Cache-Control": "no-store" });
    }

    const adminIdeaAvailMatch = path.match(/^\/api\/admin\/idea-availability\/?$/);
    if (adminIdeaAvailMatch && request.method === "GET") {
      // Each person also carries the clubs they're really in, so the admin calendar can filter by club.
      const people = await readIdeaAvailPeople(env);
      const clubsByUser = {};
      for (const clubId of await clubIdList(env)) {
        for (const uid of await readClubMemberIds(env, clubId)) (clubsByUser[uid] = clubsByUser[uid] || []).push(clubId);
      }
      const withClubs = people.map((p) => ({ ...p, clubs: p.id.startsWith("m:") ? (clubsByUser[p.id.slice(2)] || []) : [] }));
      if (leadCtx) return jsonResponse({ people: withClubs.filter((p) => p.clubs.some((c) => leadCtx.clubs.includes(c))).map((p) => ({ ...p, clubs: p.clubs.filter((c) => leadCtx.clubs.includes(c)) })) }, 200, corsHeaders);
      return jsonResponse({ people: withClubs }, 200, corsHeaders);
    }

    const adminIdeaMatch = path.match(/^\/api\/admin\/club-ideas\/([^/]+)\/([^/]+)\/?$/);
    if (adminIdeaMatch && (request.method === "DELETE" || request.method === "PUT")) {
      const clubId = decodeURIComponent(adminIdeaMatch[1]);
      const ideaId = decodeURIComponent(adminIdeaMatch[2]);
      const ideas = await readClubIdeas(env, clubId);
      const idea = ideas.find((i) => i.id === ideaId);
      if (!idea) return jsonResponse({ error: "Option not found" }, 404, corsHeaders);
      if (request.method === "DELETE") {
        const rest = ideas.filter((i) => i.id !== ideaId);
        await writeClubIdeas(env, clubId, rest);
        return jsonResponse({ ideas: sortedPublicIdeas(rest, null) }, 200, corsHeaders);
      }
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (body.title !== undefined) {
        const title = String(body.title || "").replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim();
        if (title.length < 3 || title.length > 80) return jsonResponse({ error: "The title needs 3–80 characters" }, 400, corsHeaders);
        idea.title = title;
      }
      _calIdeaCache = null;
      if (body.mapUrl !== undefined) {
        const mapUrl = String(body.mapUrl || "").trim() === "" ? "" : isGoogleMapsUrl(body.mapUrl);
        if (mapUrl === null) return jsonResponse({ error: "That isn't a Google Maps link" }, 400, corsHeaders);
        idea.mapUrl = mapUrl;
      }
      if (body.cuisine !== undefined) {
        const cuisine = sanitizeCuisine(body.cuisine);
        if (clubId === CUISINE_CLUB_ID && cuisine.length < 2) return jsonResponse({ error: "The cuisine type is required for this club" }, 400, corsHeaders);
        if (cuisine) idea.cuisine = cuisine; else delete idea.cuisine;
      }
      if (body.date !== undefined) {
        const date = String(body.date || "").trim();
        if (date && (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date + "T00:00:00Z")))) return jsonResponse({ error: "Date must look like 2026-10-03" }, 400, corsHeaders);
        idea.date = date;
      }
      if (body.price !== undefined) {
        const price = sanitizePrice(body.price);
        if (price) idea.price = price; else delete idea.price;
      }
      if (body.emoji !== undefined) {
        const em = String(body.emoji || "").trim().slice(0, 8);
        if (em) idea.emoji = em; else idea.emoji = pickIdeaEmoji(idea.title, idea.cuisine, "");
      }
      if (body.done !== undefined) {
        // "We did this one" + when (admin only). A done idea stops taking votes.
        if (body.done === true) {
          const doneDate = String(body.doneDate || "").trim();
          if (doneDate && (!/^\d{4}-\d{2}-\d{2}$/.test(doneDate) || Number.isNaN(Date.parse(doneDate + "T00:00:00Z")))) return jsonResponse({ error: "The 'done on' date must look like 2026-10-03" }, 400, corsHeaders);
          idea.done = true; idea.doneDate = doneDate;
        } else { delete idea.done; delete idea.doneDate; }
      }
      if (body.votes !== undefined) {
        const want = Number(body.votes);
        if (!Number.isInteger(want) || want < 0 || want > 9999) return jsonResponse({ error: "Votes must be a whole number from 0 to 9999" }, 400, corsHeaders);
        idea.adjust = want - ideaPeople(idea).voters.length;
      }
      await writeClubIdeas(env, clubId, ideas);
      return jsonResponse({ ideas: sortedPublicIdeas(ideas, null) }, 200, corsHeaders);
    }

    // ---- Admin: approve / decline club join requests ----
    if (path === "/api/admin/join-requests" && request.method === "GET") {
      const roster = await readClubRoster(env);
      const out = [];
      for (const r of (await listJoinRequests(env)).sort((a, b) => a.at - b.at)) {
        if (leadCtx && !leadCtx.clubs.includes(r.clubId)) continue;
        const user = await readUser(env, r.userId);
        if (!user) continue;
        out.push({ clubId: r.clubId, clubTitle: (roster.find((c) => c.id === r.clubId) || {}).title || r.clubId, userId: r.userId, name: user.name, username: user.username, phone: user.phone || "", at: r.at, ranked: (user.form && Array.isArray(user.form.ranked)) ? user.form.ranked : [], why: (user.form && user.form.why) ? String(user.form.why).slice(0, 300) : "", lead: (user.form && user.form.lead) || "", standby: Array.isArray(user.waitlist) ? user.waitlist : [] });
      }
      return jsonResponse({ requests: out }, 200, corsHeaders);
    }
    const adminJoinActionMatch = path.match(/^\/api\/admin\/join-requests\/([^/]+)\/([^/]+)\/(accept|decline)\/?$/);
    if (adminJoinActionMatch && request.method === "POST") {
      const clubId = decodeURIComponent(adminJoinActionMatch[1]);
      const userId = decodeURIComponent(adminJoinActionMatch[2]);
      const key = joinReqKey(clubId, userId);
      if (!(await env.SITE_DATA.get(key))) return jsonResponse({ error: "That request is no longer pending" }, 404, corsHeaders);
      if (adminJoinActionMatch[3] === "accept") {
        if (!(await readUser(env, userId))) { await env.SITE_DATA.delete(key); return jsonResponse({ error: "That member no longer exists" }, 404, corsHeaders); }
        if (!(await isKnownClubId(env, clubId))) return jsonResponse({ error: "That club no longer exists" }, 404, corsHeaders);
        const ids = await readClubMemberIds(env, clubId);
        if (!ids.includes(userId)) { ids.push(userId); await writeClubMemberIds(env, clubId, ids); }
      }
      await env.SITE_DATA.delete(key);
      // Tell the member next time they open the app (shown once, then cleared): accepted or not approved.
      try {
        const noticeKey = `notice:${userId}`;
        const existing = JSON.parse((await env.SITE_DATA.get(noticeKey)) || "[]");
        const clubTitle = ((await readClubRoster(env)).find((c) => c.id === clubId) || {}).title || "the club";
        existing.push({ id: crypto.randomUUID(), type: adminJoinActionMatch[3] === "accept" ? "accepted" : "declined", clubId, clubTitle, at: Date.now() });
        await env.SITE_DATA.put(noticeKey, JSON.stringify(existing.slice(-10)));
        ctx.waitUntil(sendPushToUser(env, userId, adminJoinActionMatch[3] === "accept" ? { title: "You're in! 🎉", body: `Your request to join ${clubTitle} was approved.`, url: "/#/clubs", cat: "clubs" } : { title: "Update on your request", body: `Your request to join ${clubTitle} wasn't approved this time.`, url: "/#/clubs", cat: "clubs" }).catch(() => {}));
      } catch {}
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }

    const adminClubMembersCreateMatch = path.match(/^\/api\/admin\/club-members\/([^/]+)\/?$/);
    if (adminClubMembersCreateMatch && request.method === "POST") {
      const clubId = decodeURIComponent(adminClubMembersCreateMatch[1]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const memberIds = await readClubMemberIds(env, clubId);

      // Adding someone who already has a profile (picked from the existing-members list) just
      // puts them in this club too - the username/login/edit tools are where their clubs get
      // changed, so this form only ever creates brand-new people now.
      if (body.existingUserId) {
        const user = await readUser(env, String(body.existingUserId));
        if (!user) return jsonResponse({ error: "That member no longer exists" }, 404, corsHeaders);
        if (!memberIds.includes(user.id)) {
          memberIds.push(user.id);
          await writeClubMemberIds(env, clubId, memberIds);
        }
        return jsonResponse({ id: user.id, name: user.name, username: user.username, addedExisting: true }, 200, corsHeaders);
      }

      const name = String(body.name || "").trim().slice(0, 60);
      if (!name) return jsonResponse({ error: "Name is required" }, 400, corsHeaders);
      const username = await generateUniqueUsername(env, name);
      if (!username) return jsonResponse({ error: "Please enter a first name and last initial (e.g. Amina K.)" }, 400, corsHeaders);
      if (clubId !== "none" && !(await isKnownClubId(env, clubId))) return jsonResponse({ error: "That club no longer exists" }, 404, corsHeaders);
      // Same name as an existing profile = almost certainly the same person: stop (this is how ayana.s2 / .s3 happened)
      // unless the admin explicitly says it's a different person.
      if (username !== usernameBaseFromName(name) && body.allowDuplicate !== true) {
        const norm = (n) => String(n || "").toLowerCase().replace(/[^a-z0-9]/g, "");
        let cursor;
        do {
          const page = await env.SITE_DATA.list({ prefix: "user:", cursor });
          const hit = page.keys.find((k) => norm(k.metadata && k.metadata.name) === norm(name));
          if (hit) return jsonResponse({ error: `There's already a profile called ${name}. Search for her instead — or confirm it's a different person.`, duplicate: true }, 409, corsHeaders);
          cursor = page.list_complete ? undefined : page.cursor;
        } while (cursor);
      }
      // Not everyone has an account yet — admin-created profiles all start on the same PIN 1234 so
      // Lujane doesn't have to hand out/track a different code per person; the member is required to
      // pick their own on first sign-in (mustChangePin, enforced client-side right after /api/login).
      const pin = "1234";
      const user = { id: crypto.randomUUID(), name, username, pinHash: await sha256Hex(pin), photo: null, createdAt: Date.now(), mustChangePin: true };
      const phone = sanitizePhone(body.phone);
      if (phone) user.phone = phone;
      await writeUser(env, user);
      await reserveUsername(env, username, user.id);
      if (clubId !== "none") { memberIds.push(user.id); await writeClubMemberIds(env, clubId, memberIds); } // 'none' = a profile with no club yet
      return jsonResponse({ id: user.id, name: user.name, username: user.username, pin }, 201, corsHeaders);
    }

    const adminMemberByIdMatch = path.match(/^\/api\/admin\/club-members\/([^/]+)\/([^/]+)\/?$/);
    if (adminMemberByIdMatch && request.method === "PUT") {
      const userId = decodeURIComponent(adminMemberByIdMatch[2]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const user = await readUser(env, userId);
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      if (body.name !== undefined) {
        const name = String(body.name || "").trim().slice(0, 60);
        if (!name) return jsonResponse({ error: "Name is required" }, 400, corsHeaders);
        user.name = name;
      }
      if (body.username !== undefined) {
        const username = sanitizeUsername(body.username);
        if (!username) return jsonResponse({ error: "Username must look like firstname.initial (e.g. amina.k)" }, 400, corsHeaders);
        if (username !== user.username) {
          if (await findUserIdByUsername(env, username)) return jsonResponse({ error: "That username is already taken" }, 409, corsHeaders);
          await releaseUsername(env, user.username);
          await reserveUsername(env, username, user.id);
          user.username = username;
        }
      }
      if (body.pin !== undefined) {
        const pin = String(body.pin || "").trim();
        if (!/^\d{4}$/.test(pin)) return jsonResponse({ error: "PIN must be exactly 4 digits" }, 400, corsHeaders);
        user.pinHash = await sha256Hex(pin);
      }
      if (body.phone !== undefined) {
        const phone = sanitizePhone(body.phone);
        if (body.phone && !phone) return jsonResponse({ error: "That doesn't look like a phone number" }, 400, corsHeaders);
        if (phone) user.phone = phone; else delete user.phone;
      }
      await writeUser(env, user);
      return jsonResponse(publicUser(user), 200, corsHeaders);
    }

    const adminResetMatch = path.match(/^\/api\/admin\/club-members\/([^/]+)\/([^/]+)\/reset-pin\/?$/);
    if (adminResetMatch && request.method === "POST") {
      const userId = decodeURIComponent(adminResetMatch[2]);
      const user = await readUser(env, userId);
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      const pin = randomPin();
      user.pinHash = await sha256Hex(pin);
      await writeUser(env, user);
      return jsonResponse({ pin }, 200, corsHeaders);
    }

    const adminDeleteMatch = path.match(/^\/api\/admin\/club-members\/([^/]+)\/([^/]+)\/?$/);
    if (adminDeleteMatch && request.method === "DELETE") {
      const clubId = decodeURIComponent(adminDeleteMatch[1]);
      const userId = decodeURIComponent(adminDeleteMatch[2]);
      const memberIds = await readClubMemberIds(env, clubId);
      if (leadCtx && !(await allClubIdsContaining(env, userId)).some((c) => c !== clubId)) {
        return jsonResponse({ error: "They're only in this club — removing them would delete their profile, so ask the main admin." }, 409, corsHeaders);
      }
      await writeClubMemberIds(env, clubId, memberIds.filter(id => id !== userId));
      // Only delete the global identity once they're not in any club anymore.
      const remainingClubs = await allClubIdsContaining(env, userId);
      if (!remainingClubs.length) {
        const user = await readUser(env, userId);
        if (user) await releaseUsername(env, user.username);
        await deleteUser(env, userId);
      }
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }

    // Admin: change which clubs a member belongs to (add/remove any number at once)
    // Admin: EVERY profile, whether or not they're in a club yet (club-members only lists club members).
    if (path === "/api/admin/users" && request.method === "GET") {
      const SEEN = await seenMap(env);
      try {
      const clubsByUser = {};
      for (const clubId of await clubIdList(env)) {
        for (const uid of await readClubMemberIds(env, clubId)) (clubsByUser[uid] = clubsByUser[uid] || []).push(clubId);
      }
      const pendingByUser = {};
      for (const r of await listJoinRequests(env)) (pendingByUser[r.userId] = pendingByUser[r.userId] || []).push(r.clubId);
      const squadsByUser = {};
      for (const sid of Object.keys(SQUAD_TITLES)) for (const uid of await readSquadMemberIds(env, sid)) (squadsByUser[uid] = squadsByUser[uid] || []).push(SQUAD_TO_CLUB[sid]);
      const out = [];
      for (const u of await listAllUsers(env)) {
          if (u) out.push({ ...publicUser(u), waRemindedAt: u.waRemindedAt || 0, formRanked: (u.form && Array.isArray(u.form.ranked)) ? u.form.ranked : [], stayClubs: squadsByUser[u.id] || [], stayAt: u.stayConfirmedAt || 0, phone: u.phone || "", createdAt: u.createdAt || 0, ...seenOf(SEEN, u), archived: u.archived || null, clubs: clubsByUser[u.id] || [], pending: pendingByUser[u.id] || [], push: (await readPushSubs(env, u.id)).length > 0 });
      }
      if (leadCtx) return jsonResponse({ users: out.filter((u) => (u.clubs || []).some((c) => leadCtx.clubs.includes(c))).map((u) => ({ ...u, clubs: u.clubs.filter((c) => leadCtx.clubs.includes(c)), pending: (u.pending || []).filter((c) => leadCtx.clubs.includes(c)) })) }, 200, corsHeaders);
      if (!leadCtx) saveSnapshot(env, "snap:adminUsers", out);
      return jsonResponse({ users: out }, 200, corsHeaders);
      } catch (e) {
        // a KV limit/outage: show the last good copy of the profile list instead of an empty page
        const snap = leadCtx ? null : await readSnapshot(env, "snap:adminUsers");
        if (snap && Array.isArray(snap.data)) return jsonResponse({ users: snap.data, stale: true, staleAt: snap.at }, 200, corsHeaders);
        return jsonResponse({ error: "Cloudflare's free daily limit was reached — nothing was deleted. It resets at 8 PM Toronto time." }, 503, corsHeaders);
      }
    }
    // Admin: send a notification to chosen members (or everyone who turned notifications on).
    if (path === "/api/admin/push/send" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const title = String(body.title || "").replace(/[\x00-\x1f]/g, " ").trim().slice(0, 80);
      const text = String(body.body || "").replace(/[\x00-\x1f]/g, " ").trim().slice(0, 240);
      if (!title || !text) return jsonResponse({ error: "A title and a message are required" }, 400, corsHeaders);
      const link = typeof body.url === "string" && /^\/[#/A-Za-z0-9._~!$&'()*+,;=:@%-]*$/.test(body.url) ? body.url : "/";
      const ids = [...new Set((Array.isArray(body.userIds) ? body.userIds : []).map(String))].slice(0, 500);
      let sent = 0, noPush = 0, removed = 0, muted = 0;
      for (const id of ids) {
        const r = await sendPushToUser(env, id, { title, body: text, url: link, cat: NOTIF_CATS.includes(body.category) ? body.category : "announcements" });
        if (r.muted) muted++; else if (!r.devices) noPush++; else { sent += r.sent; removed += r.removed; }
      }
      await env.SITE_DATA.put("meta:lastRemind:push", JSON.stringify({ at: Date.now(), sent, noPush, asked: ids.length, title }));
      return jsonResponse({ sent, noPush, removed, muted, asked: ids.length }, 200, corsHeaders);
    }
    // Admin: when did I last remind people? (shown as a disclaimer before sending another one)
    if (path === "/api/admin/reminders/last" && request.method === "GET") {
      const read = async (k) => { try { return JSON.parse((await env.SITE_DATA.get(k)) || "null"); } catch { return null; } };
      return jsonResponse({ app: await read("meta:lastRemind:app"), push: await read("meta:lastRemind:push") }, 200, corsHeaders);
    }
    // Admin: nudge people to add their availability — they see a one-time pop-up next time they open the app.
    if (path === "/api/admin/remind-availability" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const ids = [...new Set((Array.isArray(body.userIds) ? body.userIds : []).map(String))].slice(0, 500);
      let reminded = 0;
      for (const id of ids) {
        if (!(await readUser(env, id))) continue;
        const key = `notice:${id}`;
        let list = [];
        try { list = JSON.parse((await env.SITE_DATA.get(key)) || "[]"); } catch {}
        if (list.some((n) => n.type === "remind")) continue; // one pending reminder is enough
        list.push({ id: crypto.randomUUID(), type: "remind", at: Date.now() });
        await env.SITE_DATA.put(key, JSON.stringify(list.slice(-10)));
        reminded++;
      }
      await env.SITE_DATA.put("meta:lastRemind:app", JSON.stringify({ at: Date.now(), count: reminded, asked: ids.length }));
      return jsonResponse({ reminded, skipped: ids.length - reminded }, 200, corsHeaders);
    }
    // Admin: delete a whole profile (not just one club membership): memberships, join requests, availability, username.
    // Admin: merge two accidental duplicate accounts. Without confirm it only previews; with confirm the account with more info is kept and the other is folded into it.
    if (path === "/api/admin/users-merge" && request.method === "POST") {
      let b; try { b = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const resolve = async (v) => { v = String(v || "").trim().toLowerCase(); if (!v) return null; const byId = await readUser(env, v).catch(() => null); if (byId) return byId; const id = await findUserIdByUsername(env, v); return id ? await readUser(env, id) : null; };
      const A = await resolve(b.a), B = await resolve(b.b);
      if (!A || !B || A.id === B.id) return jsonResponse({ error: "Couldn't find two different accounts for those usernames." }, 404, corsHeaders);
      const clubsOf = async (u) => { const out = []; for (const c of await clubIdList(env)) if ((await readClubMemberIds(env, c)).includes(u.id)) out.push(c); return out; };
      const stepRows = async (u) => ((await env.DB.prepare("SELECT COUNT(*) AS n FROM steps_daily WHERE user_id = ?").bind(u.id).first()) || {}).n || 0;
      const info = async (u) => { const filled = Object.entries(u).filter(([k, v]) => !["id", "pinHash", "token"].includes(k) && v != null && v !== "" && !(Array.isArray(v) && !v.length) && !(typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length)).length; const clubs = await clubsOf(u), steps = await stepRows(u), hasAvail = !!(await readIaDoc(env, `m:${u.id}`)); return { id: u.id, name: u.name, username: u.username, filled, clubs, steps, hasAvail, score: filled * 3 + clubs.length * 2 + (hasAvail ? 4 : 0) + Math.min(steps, 30) / 3 }; };
      const iA = await info(A), iB = await info(B);
      const keepId = b.keep ? String(b.keep) : (iA.score >= iB.score ? A.id : B.id);
      if (![A.id, B.id].includes(keepId)) return jsonResponse({ error: "keep must be one of the two accounts" }, 400, corsHeaders);
      const K = keepId === A.id ? A : B, D = keepId === A.id ? B : A, iK = keepId === A.id ? iA : iB, iD = keepId === A.id ? iB : iA;
      if (!b.confirm) return jsonResponse({ preview: true, keep: iK, drop: iD }, 200, corsHeaders);
      // 1. fill every empty field on the kept profile from the other one
      for (const [k, v] of Object.entries(D)) { if (["id", "username", "pinHash", "token", "archived"].includes(k)) continue; const cur = K[k]; const empty = cur == null || cur === "" || (Array.isArray(cur) && !cur.length) || (typeof cur === "object" && !Array.isArray(cur) && !Object.keys(cur).length); if (empty && v != null && v !== "") K[k] = v; }
      await writeUser(env, K);
      // 2. clubs: union
      for (const c of iD.clubs) { const ids = await readClubMemberIds(env, c); if (!ids.includes(K.id)) { ids.push(K.id); } await writeClubMemberIds(env, c, ids.filter((x) => x !== D.id)); }
      // 3. availability: keep theirs, else take the other's
      if (!iK.hasAvail) { const raw = await readIaDoc(env, `m:${D.id}`); if (raw) await writeIaDoc(env, `m:${K.id}`, raw); }
      // 4. club-event answers
      for (const c of await clubIdList(env)) { for (const ev of await readClubEvents(env, c).catch(() => [])) { const key = clubEventResponsesKey(c, ev.id), raw = await env.SITE_DATA.get(key); if (!raw) continue; let r; try { r = JSON.parse(raw); } catch { continue; } if (r[D.id]) { if (!r[K.id]) r[K.id] = r[D.id]; delete r[D.id]; await env.SITE_DATA.put(key, JSON.stringify(r)); } } }
      // 5. D1 rows that point at a user
      const mv = async (sql, ...args) => { try { await env.DB.prepare(sql).bind(...args).run(); } catch {} };
      await mv("UPDATE OR IGNORE steps_daily SET user_id = ? WHERE user_id = ?", K.id, D.id);
      await mv("UPDATE OR IGNORE step_participants SET user_id = ? WHERE user_id = ?", K.id, D.id);
      await mv("UPDATE OR IGNORE step_sources SET user_id = ? WHERE user_id = ?", K.id, D.id);
      await mv("UPDATE step_pledges SET user_id = ? WHERE user_id = ?", K.id, D.id);
      await mv("UPDATE OR IGNORE device_tokens SET user_id = ? WHERE user_id = ?", K.id, D.id);
      await mv("UPDATE OR IGNORE event_reviews SET user_id = ? WHERE user_id = ?", K.id, D.id);
      await mv("UPDATE OR IGNORE gh_tokens SET user_id = ? WHERE user_id = ?", K.id, D.id);
      await mv("UPDATE bm_players SET uid = ? WHERE uid = ?", K.id, D.id);
      for (const t of ["steps_daily", "step_participants", "step_sources", "device_tokens", "event_reviews", "gh_tokens", "badge_counts", "member_seen"]) await mv(`DELETE FROM ${t} WHERE user_id = ?`, D.id);
      // 6. squads, push, requests, then remove the duplicate
      for (const sid of Object.keys(SQUAD_TITLES)) { const ids = await readSquadMemberIds(env, sid); if (ids.includes(D.id)) await writeSquadMemberIds(env, sid, [...new Set(ids.map((x) => (x === D.id ? K.id : x)))]); await env.SITE_DATA.delete(squadReqKey(sid, D.id)); }
      const reqKeys = await env.SITE_DATA.list({ prefix: "joinreq:" });
      for (const k of reqKeys.keys) if (k.name.split(":")[2] === D.id) await env.SITE_DATA.delete(k.name);
      await deleteIaDoc(env, `m:${D.id}`); _ideaAvailMemo = { at: 0, people: null };
      await env.SITE_DATA.delete(pushKey(D.id));
      await releaseUsername(env, D.username);
      await deleteUser(env, D.id);
      _memberSearchCache = null; _stepsPublicMemo = { at: 0, data: null };
      return jsonResponse({ ok: true, kept: { id: K.id, name: K.name, username: K.username }, merged: { id: D.id, username: D.username } }, 200, corsHeaders);
    }
    const adminUserDeleteMatch = path.match(/^\/api\/admin\/users\/([^/]+)\/?$/);
    if (adminUserDeleteMatch && request.method === "DELETE") {
      const userId = decodeURIComponent(adminUserDeleteMatch[1]);
      const user = await readUser(env, userId);
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      for (const clubId of await clubIdList(env)) {
        const ids = await readClubMemberIds(env, clubId);
        if (ids.includes(userId)) await writeClubMemberIds(env, clubId, ids.filter((id) => id !== userId));
      }
      const reqKeys = await env.SITE_DATA.list({ prefix: "joinreq:" });
      for (const k of reqKeys.keys) if (k.name.split(":")[2] === userId) await env.SITE_DATA.delete(k.name);
      await deleteIaDoc(env, `m:${userId}`);
      _ideaAvailMemo = { at: 0, people: null };
      await env.SITE_DATA.delete(pushKey(userId));
      for (const sid of Object.keys(SQUAD_TITLES)) { await writeSquadMemberIds(env, sid, (await readSquadMemberIds(env, sid)).filter((x) => x !== userId)); await env.SITE_DATA.delete(squadReqKey(sid, userId)); }
      await releaseUsername(env, user.username);
      await deleteUser(env, userId); // their login token stops working because the user no longer exists
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    // Admin: fill in phone numbers from the sign-up form's Formspree export ([{name, phone}]) - matches on the name
    // and only fills a profile that has no phone yet (never overwrites).
    if (path === "/api/admin/import-phones" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const rows = Array.isArray(body.rows) ? body.rows.slice(0, 3000) : [];
      const norm = (n) => String(n || "").toLowerCase().replace(/[^a-z0-9\s]/g, " ").replace(/\s+/g, " ").trim();
      const short = (n) => { const t = norm(n).split(" "); return t.length >= 2 ? `${t[0]} ${t[t.length - 1][0]}` : t[0] || ""; };
      const users = [];
      for (const u of await listAllUsers(env)) users.push(u);
      let updated = 0, alreadyHad = 0;
      const unmatched = [], ambiguous = [];
      for (const row of rows) {
        const phone = sanitizePhone(row && row.phone);
        const name = String((row && row.name) || "").trim();
        if (!name || !phone) continue;
        let hits = users.filter((u) => norm(u.name) === norm(name));
        if (!hits.length) hits = users.filter((u) => short(u.name) === short(name));
        if (!hits.length) { unmatched.push(name); continue; }
        if (hits.length > 1) { ambiguous.push(name); continue; }
        const u = hits[0];
        if (u.phone) { alreadyHad++; continue; }
        u.phone = phone; await writeUser(env, u); updated++;
      }
      return jsonResponse({ updated, alreadyHad, unmatched: unmatched.slice(0, 80), ambiguous: ambiguous.slice(0, 40), rows: rows.length }, 200, corsHeaders);
    }
    // Admin: one person's full profile (phone, joined, clubs, pending requests, last sign-in / activity)
    const adminUserProfileMatch = path.match(/^\/api\/admin\/users\/([^/]+)\/profile\/?$/);
    if (adminUserProfileMatch && request.method === "GET") {
      const SEEN = await seenMap(env);
      const userId = decodeURIComponent(adminUserProfileMatch[1]);
      const user = await readUser(env, userId);
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      return jsonResponse({
        id: user.id, name: user.name, username: user.username, photo: user.photo || null,
        phone: user.phone || "", createdAt: user.createdAt || 0, ...seenOf(SEEN, user), archived: user.archived || null, form: user.form || null,
        stayClubs: await legacySquadClubsOf(env, user.id), stayAt: user.stayConfirmedAt || 0,
        clubs: await allClubIdsContaining(env, user.id), pending: await pendingClubIdsFor(env, user.id), waitlist: Array.isArray(user.waitlist) ? user.waitlist : [],
      }, 200, corsHeaders);
    }
    const adminUserArchiveMatch = path.match(/^\/api\/admin\/users\/([^/]+)\/archive\/?$/);
    if (adminUserArchiveMatch && request.method === "PUT") {
      const userId = decodeURIComponent(adminUserArchiveMatch[1]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const user = await readUser(env, userId);
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      if (body.archived) {
        const reason = body.reason === "travelling" ? "travelling" : "past";
        const until = reason === "travelling" && isValidDateString(String(body.until || "")) ? String(body.until) : "";
        user.archived = { reason, until, at: Date.now() };
      } else delete user.archived;
      await writeUser(env, user);
      return jsonResponse({ ok: true, archived: user.archived || null }, 200, corsHeaders);
    }
    // ---- Admin: see exactly what each email looks like (nothing is sent) ----
    if (path === "/api/admin/email-preview" && request.method === "GET") {
      const kind = url.searchParams.get("kind") || "index";
      const cap = [], penv = { ...env, __capture: cap, RESEND_API_KEY: "preview", ADMIN_NOTIFY_EMAIL: "preview@example.com" };
      const pctx = { waitUntil: (p) => p };
      const user = { name: "Aaliyah K.", username: "aaliyah.k", phone: "416-555-0123", form: { ranked: ["Cuisine", "Arts & Crafts", "Field"], why: "I love trying new restaurants and would love to host a dinner night!", lead: "Yes, leading" } };
      const club = { id: "club-cuisine", title: "CUISINE" };
      const sampleEvent = { id: "sample-1", name: "Sunset Picnic at Trillium Park", date: "2026-10-18", city: "Toronto", genre: "functions", link: "https://instagram.com/p/sample", comments: "Bring a blanket — women-only, free entry!", at: Date.now() };
      const sampleRes = { id: "sample-2", title: "Sweet Saffron Bakery", type: "cafes", city: "Mississauga", link: "https://instagram.com/sweetsaffron", comments: "Halal, woman-owned, does custom cakes.", at: Date.now() };
      let msg = null;
      if (kind === "join") { notifyAdminOfJoinRequest(penv, pctx, user, club); msg = cap[0]; }
      else if (kind === "event") { await notifyAdminOfSuggestion(penv, pctx, "event", sampleEvent); msg = cap[0]; }
      else if (kind === "resource") { await notifyAdminOfSuggestion(penv, pctx, "resource", sampleRes); msg = cap[0]; }
      else if (kind === "backup") { await sendBackupEmail(penv, "Daily backup"); msg = cap[0]; }
      else if (kind === "digest") msg = { subject: "What's on today", html: digestEmailHtml(env, "Sunday, October 18", [{ title: "Pilates at the Lake", date: "Today · 10:00 AM", location: "Toronto" }, { title: "Sisters Quran circle", date: "Today · 7:30 PM", location: "Mississauga" }], "#", "#") };
      if (kind === "index" || !msg) {
        const links = [["join", "🙋‍♀️ Join request"], ["event", "🗓️ Event submitted"], ["resource", "🛍️ Resource submitted"], ["backup", "🛟 Daily backup"], ["digest", "☀️ Daily digest (subscribers)"]];
        return new Response(`<!DOCTYPE html><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:Arial;background:#fef7f4;padding:24px"><h2 style="color:#76220b">Email previews</h2><p>Nothing is sent — these are examples with made-up people.</p>${links.map(([k, l]) => `<p><a href="?kind=${k}" style="color:#76220b;font-size:18px">${l}</a></p>`).join("")}</body>`, { headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" } });
      }
      return new Response(msg.html, { headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" } });
    }
    // ---- Admin: backups (download now / email now) ----
    if (path === "/api/admin/backup" && request.method === "GET") {
      const b = await buildBackup(env);
      return new Response(JSON.stringify(b, null, 1), { status: 200, headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="4dasistas-backup-${b.at.slice(0, 10)}.json"`, "Cache-Control": "no-store", ...corsHeaders } });
    }
    if (path === "/api/admin/backup-email" && request.method === "POST") {
      const r = await sendBackupEmail(env, "Backup you requested");
      return jsonResponse(r, r.ok ? 200 : 500, corsHeaders);
    }
    // ---- Admin: D1 database status + the ONE-TIME move of profiles and availability from KV into D1 (idempotent, KV copies are kept as a backup) ----
    if (path === "/api/admin/d1-status" && request.method === "GET") {
      if (!env.DB) return jsonResponse({ bound: false, migrated: false }, 200, corsHeaders);
      await d1Ensure(env);
      const m = await env.DB.prepare("SELECT v FROM meta WHERE k = 'migrated'").first();
      const u = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
      const a = await env.DB.prepare("SELECT COUNT(*) AS n FROM ideaavail").first();
      return jsonResponse({ bound: true, migrated: !!(m && m.v === "1"), users: u ? u.n : 0, availability: a ? a.n : 0 }, 200, corsHeaders);
    }
    if (path === "/api/admin/d1-migrate" && request.method === "POST") {
      if (!env.DB) return jsonResponse({ error: "No D1 database is attached to the Worker yet." }, 400, corsHeaders);
      await d1Ensure(env);
      _d1Mode = { at: 0, on: false }; // read the source from KV for the copy
      const kvUser = async (id) => { const raw = await env.SITE_DATA.get(userKey(id)); try { return raw ? JSON.parse(raw) : null; } catch { return null; } };
      // who exists: the index / list, plus everyone reachable through club membership (plain GETs) so nobody is missed if lists are blocked
      const ids = new Set(await allUserIds(env));
      for (const id of await idsFromClubMembers(env)) ids.add(id);
      const userStmts = []; let users = 0;
      for (const id of ids) { const u = await kvUser(id); if (!u) continue; users++; userStmts.push(env.DB.prepare("INSERT OR REPLACE INTO users (id, name, username, data) VALUES (?, ?, ?, ?)").bind(u.id, u.name || "", u.username || "", JSON.stringify(u))); }
      const iaIds = new Set((await readIndex(env, IA_INDEX_KEY)) || []);
      for (const id of ids) iaIds.add(`m:${id}`);
      iaIds.add("admin");
      const iaStmts = []; let avail = 0;
      for (const pid of iaIds) { const raw = await env.SITE_DATA.get(ideaAvailKey(pid)); if (!raw) continue; avail++; iaStmts.push(env.DB.prepare("INSERT OR REPLACE INTO ideaavail (person_id, data) VALUES (?, ?)").bind(pid, raw)); }
      for (const stmts of [userStmts, iaStmts]) for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
      const nU = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first()).n, nA = (await env.DB.prepare("SELECT COUNT(*) AS n FROM ideaavail").first()).n;
      if (nU < users) return jsonResponse({ error: `The copy looks incomplete (${nU} of ${users} profiles) — nothing was switched.` }, 500, corsHeaders);
      await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('migrated', '1')").run();
      _d1Mode = { at: Date.now(), on: true };
      return jsonResponse({ ok: true, users: nU, availability: nA, found: users }, 200, corsHeaders);
    }
    if (path === "/api/admin/d1-rollback" && request.method === "POST") {
      if (!env.DB) return jsonResponse({ error: "No D1 database attached." }, 400, corsHeaders);
      await d1Ensure(env);
      await env.DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('migrated', '0')").run();
      _d1Mode = { at: Date.now(), on: false };
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }
    // Wording of the WhatsApp messages the admin sends (availability reminder, notifications nudge, club accepted / declined). {first} {name} {club} are filled in.
    const WA_KEYS = ["remind", "notif", "joinAccept", "joinDecline", "newPeriod", "welcome", "eventRemind", "payRemind", "stayRemind"];
    if (path === "/api/admin/wa-templates" && request.method === "GET") {
      let t = {}; try { t = JSON.parse((await env.SITE_DATA.get("watemplates")) || "{}") || {}; } catch {}
      return jsonResponse({ templates: t }, 200, corsHeaders);
    }
    if (path === "/api/admin/wa-templates" && request.method === "PUT") {
      let body; try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const out = {};
      for (const k of WA_KEYS) { const v = String((body.templates || {})[k] || "").replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, " ").trim().slice(0, 1800); if (v) out[k] = v; }
      await env.SITE_DATA.put("watemplates", JSON.stringify(out));
      return jsonResponse({ ok: true, templates: out }, 200, corsHeaders);
    }
    // Admin / club admin: remember that a WhatsApp availability reminder was sent to this person.
    const adminUserRemindedMatch = path.match(/^\/api\/admin\/users\/([^/]+)\/reminded\/?$/);
    if (adminUserRemindedMatch && request.method === "POST") {
      const user = await readUser(env, decodeURIComponent(adminUserRemindedMatch[1]));
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      user.waRemindedAt = Date.now();
      await writeUser(env, user);
      return jsonResponse({ ok: true, waRemindedAt: user.waRemindedAt }, 200, corsHeaders);
    }
    // Admin: attach what a person wrote on the sign-up form (clubs ranked, comments) to their profile; fills a missing phone number only.
    const adminUserFormMatch = path.match(/^\/api\/admin\/users\/([^/]+)\/signup-form\/?$/);
    if (adminUserFormMatch && request.method === "PUT") {
      const userId = decodeURIComponent(adminUserFormMatch[1]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const user = await readUser(env, userId);
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      const form = sanitizeSignupForm(body, "import");
      if (form) user.form = form;
      let phoneFilled = false;
      if (!user.phone && body.phone) { const p = sanitizePhone(body.phone); if (p) { user.phone = p; phoneFilled = true; } }
      await writeUser(env, user);
      return jsonResponse({ ok: true, formSaved: !!form, phoneFilled }, 200, corsHeaders);
    }
    // Admin: create a bare profile (no club yet) from a sign-up form. PIN starts as 1234 and they must choose their own at first sign-in.
    if (path === "/api/admin/users" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const name = sanitizePersonName(body.name);
      if (!name) return jsonResponse({ error: "A name is required" }, 400, corsHeaders);
      const username = await generateUniqueUsername(env, name);
      const user = { id: crypto.randomUUID(), name, username, pinHash: await sha256Hex("1234"), photo: null, createdAt: Date.now(), mustChangePin: true };
      const phone = sanitizePhone(body.phone); if (phone) user.phone = phone;
      const form = sanitizeSignupForm(body, "import"); if (form) user.form = form;
      await writeUser(env, user);
      await reserveUsername(env, username, user.id);
      return jsonResponse({ ok: true, id: user.id, username, name }, 201, corsHeaders);
    }
    const adminUserClubsMatch = path.match(/^\/api\/admin\/users\/([^/]+)\/clubs\/?$/);
    if (adminUserClubsMatch && request.method === "PUT") {
      const userId = decodeURIComponent(adminUserClubsMatch[1]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!Array.isArray(body.clubs)) return jsonResponse({ error: "clubs must be an array of club ids" }, 400, corsHeaders);
      const user = await readUser(env, userId);
      if (!user) return jsonResponse({ error: "Not found" }, 404, corsHeaders);
      const desired = new Set(body.clubs.map(String));
      const current = new Set(await allClubIdsContaining(env, userId));
      const toAdd = [...desired].filter(c => !current.has(c));
      const toRemove = [...current].filter(c => !desired.has(c));
      for (const clubId of toAdd) {
        const ids = await readClubMemberIds(env, clubId);
        if (!ids.includes(userId)) { ids.push(userId); await writeClubMemberIds(env, clubId, ids); }
      }
      for (const clubId of toRemove) {
        const ids = await readClubMemberIds(env, clubId);
        await writeClubMemberIds(env, clubId, ids.filter(id => id !== userId));
      }
      if (!desired.size) {
        await releaseUsername(env, user.username);
        await deleteUser(env, userId);
        return jsonResponse({ ok: true, deleted: true }, 200, corsHeaders);
      }
      return jsonResponse({ ok: true, clubs: [...desired] }, 200, corsHeaders);
    }

    // Admin: create/list/delete per-club events
    // ---- Club calendar admin: main admin = every club; a club admin = only their own clubs ----
    if (path === "/api/admin/club-cal/image" && request.method === "POST") { // photos for an event page (main admin or a club admin)
      const r = await calImgSave(request, env, String(url.searchParams.get("ev") || "").slice(0, 60));
      return r.error ? jsonResponse({ error: r.error }, 400, corsHeaders) : jsonResponse(r, 201, corsHeaders);
    }
    const adminCalRespMatch = path.match(/^\/api\/admin\/club-cal\/([^/]+)\/responses\/?$/);
    if (adminCalRespMatch && request.method === "GET") {
      const ev = (await readClubCal(env)).find((e) => e.id === adminCalRespMatch[1]);
      if (!ev || (leadCtx && !(Array.isArray(ev.formLeads) && ev.formLeads.includes(leadCtx.username)))) return jsonResponse({ error: leadCtx && ev ? "Ask the main admin to give you access to this event's form" : "Event not found" }, leadCtx && ev ? 403 : 404, corsHeaders);
      let map = {}; try { map = JSON.parse((await env.SITE_DATA.get(calFormKey(ev.id))) || "{}") || {}; } catch {}
      return jsonResponse({ form: ev.form || null, responses: Object.keys(map).map((uid) => ({ userId: uid, name: map[uid].name, contact: map[uid].contact || "", guest: !!map[uid].guest, paid: !!((ev.rsvps || []).find((x) => x.id === uid) || {}).paid, claimedPaid: !!((ev.rsvps || []).find((x) => x.id === uid) || {}).claimedPaid, status: ((ev.rsvps || []).find((x) => x.id === uid) || {}).status || "", addons: map[uid].addons || [], total: map[uid].total ?? null, answers: map[uid].answers, at: map[uid].at })).sort((a, b) => a.at - b.at) }, 200, corsHeaders);
    }
    const adminCalMatch = path.match(/^\/api\/admin\/club-cal(?:\/([^/]+)(?:\/rsvp\/([^/]+)\/(accept|decline|remove|add|paid|unpaid)|\/(message|edit-link|restore))?)?\/?$/);
    if (adminCalMatch) {
      const M = request.method;
      const canClub = (cid) => !leadCtx || leadCtx.clubs.includes(cid);
      // A club admin manages any event their club is part of (collabs included) — but an event's FORM (editing it, the answers, who's paid) is only theirs when the main admin ticked them in `formLeads`.
      const canForm = (e) => !leadCtx || (Array.isArray(e.formLeads) && e.formLeads.includes(leadCtx.username));
      const canEv = (e) => calClubs(e).some(canClub) || canForm(e);
      const roster = await readClubRoster(env);
      const clubTitle = (id) => (roster.find((c) => c.id === id) || {}).title || "";
      const view = (e) => ({ id: e.id, slug: e.slug || "", clubId: e.clubId, clubIds: calClubs(e), clubTitle: calClubs(e).map(clubTitle).filter(Boolean).join(" × "), title: e.title, date: e.date, time: e.time || "", place: e.place || "", mapUrl: e.mapUrl || "", desc: e.desc || "", blocks: e.blocks || [], theme: e.theme || null, hosts: e.hosts || [], editToken: canForm(e) ? (e.editToken || "") : "", histN: e.histN || 0, rsvpBy: e.rsvpBy || "", form: canForm(e) ? (e.form || null) : null, hasForm: !!e.form, canForm: canForm(e), ...(leadCtx ? {} : { formLeads: e.formLeads || [] }), publicForm: !!e.publicForm, capacity: calCap(e), rsvps: e.rsvps || [], ...(e.tbd ? { tbd: true, interest: e.interest || [] } : {}) });
      const all = await readClubCal(env);
      if (!adminCalMatch[1] && M === "GET") return jsonResponse({ events: all.filter(canEv).sort((a, b) => a.date.localeCompare(b.date)).map(view) }, 200, corsHeaders);
      let body = {};
      if ((M === "POST" || M === "PUT") && !adminCalMatch[2]) { try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); } }
      if (!adminCalMatch[1] && M === "POST") {
        const clubIds = [...new Set((Array.isArray(body.clubIds) ? body.clubIds : [body.clubId]).map(String))].filter((id) => roster.some((c) => c.id === id)).slice(0, 8);
        if (!clubIds.length) return jsonResponse({ error: "Pick at least one club" }, 400, corsHeaders);
        if (!clubIds.some(canClub)) return jsonResponse({ error: "You can only add events for your own clubs" }, 403, corsHeaders);
        const clubId = clubIds[0];
        if (String(body.mapUrl || "").trim() && !isGoogleMapsUrl(body.mapUrl)) return jsonResponse({ error: "That isn't a Google Maps link — in Google Maps tap Share → Copy link" }, 400, corsHeaders);
        const f = calFields(body);
        if (f.title.length < 3) return jsonResponse({ error: "Give the event a name (3+ letters)" }, 400, corsHeaders);
        const tbd = !!body.tbd; // "date to be decided": members of the club can show interest instead of RSVPing
        if (tbd) { f.date = ""; f.rsvpBy = ""; } else if (!isValidDateString(f.date)) return jsonResponse({ error: "Pick a date" }, 400, corsHeaders);
        const ev = { id: crypto.randomUUID(), clubId, clubIds, ...f, ...calDesignFieldsObj(body), ...(tbd ? { tbd: true, interest: [] } : {}), rsvps: [], at: Date.now() };
        { const cf = sanitizeCalForm(body.form); if (cf && !tbd) { if (cf.rsvpBy !== undefined) { ev.rsvpBy = cf.rsvpBy || ev.rsvpBy || ""; } if (cf.desc !== undefined) ev.desc = cf.desc; delete cf.rsvpBy; delete cf.desc; ev.form = cf; if (leadCtx) ev.formLeads = [leadCtx.username]; } }
        if (body.publicForm) ev.publicForm = true;
        // Attendees chosen right in the "Add event" form: members (by id) and people without a profile (by name).
        for (const at of (Array.isArray(body.attendees) ? body.attendees : []).slice(0, 200)) {
          if (at && at.userId) { const u = await readUser(env, String(at.userId)); if (u && !ev.rsvps.some((r) => r.id === u.id)) ev.rsvps.push({ id: u.id, name: sanitizePersonName(u.name) || "Member", status: "going", at: Date.now(), added: true }); }
          else if (at && sanitizePersonName(at.name).length >= 2) ev.rsvps.push({ id: `g:${crypto.randomUUID().slice(0, 12)}`, name: sanitizePersonName(at.name), status: "going", at: Date.now(), added: true, guest: true });
        }
        ev.slug = calMakeSlug(all, ev); all.push(ev); await writeClubCal(env, all);
        return jsonResponse({ ok: true, event: view(ev) }, 201, corsHeaders);
      }
      const ev = all.find((e) => e.id === adminCalMatch[1]);
      if (!ev || !canEv(ev)) return jsonResponse({ error: "Event not found" }, 404, corsHeaders);
      if (!adminCalMatch[2] && M === "PUT") {
        if (Array.isArray(body.clubIds)) {
          const ids = [...new Set(body.clubIds.map(String))].filter((id) => roster.some((c) => c.id === id)).slice(0, 8);
          if (!ids.length) return jsonResponse({ error: "Pick at least one club" }, 400, corsHeaders);
          if (!ids.some(canClub)) return jsonResponse({ error: "Keep at least one of your own clubs on the event" }, 403, corsHeaders);
          ev.clubIds = ids; ev.clubId = ids[0];
        }
        if (body.mapUrl !== undefined && String(body.mapUrl || "").trim() && !isGoogleMapsUrl(body.mapUrl)) return jsonResponse({ error: "That isn't a Google Maps link — in Google Maps tap Share → Copy link" }, 400, corsHeaders);
        const f = calFields({ ...ev, ...body });
        if (f.title.length < 3) return jsonResponse({ error: "Give the event a name (3+ letters)" }, 400, corsHeaders);
        const wantTbd = body.tbd !== undefined ? !!body.tbd : !!ev.tbd;
        if (wantTbd) { f.date = ""; f.rsvpBy = ""; } else if (!isValidDateString(f.date)) return jsonResponse({ error: "Pick a date" }, 400, corsHeaders);
        const capBefore = calCap(ev), titleBefore = ev.title;
        Object.assign(ev, f); calApplyDesign(ev, calDesignFields(body));
        if (ev.slug && ev.title !== titleBefore) { ev.oldSlugs = [...new Set([...(ev.oldSlugs || []), ev.slug])].slice(-5); ev.slug = ""; ev.slug = calMakeSlug(all, ev); } // renamed: new readable link, the old one still works
        if (wantTbd) { ev.tbd = true; ev.interest = ev.interest || []; } else delete ev.tbd; // (the interest list stays on the event so the admin still sees who was keen)
        if (body.form !== undefined) { // (a club admin without access never sees the form, so their edit of the event details must not touch it)
          const cf = sanitizeCalForm(body.form);
          if (cf) { if (cf.rsvpBy !== undefined && (canForm(ev) || !ev.form)) ev.rsvpBy = cf.rsvpBy; if (cf.desc !== undefined && (canForm(ev) || !ev.form)) ev.desc = cf.desc; delete cf.rsvpBy; delete cf.desc; }
          if (canForm(ev)) { if (cf) ev.form = cf; else delete ev.form; }
          else if (!ev.form && cf) { ev.form = cf; ev.formLeads = [...new Set([...(ev.formLeads || []), leadCtx.username])]; } // they created the form, so it's theirs
        }
        if (body.formLeads !== undefined && !leadCtx) {
          const names = [...new Set((Array.isArray(body.formLeads) ? body.formLeads : []).map(String))].slice(0, 30), good = [];
          for (const u of names) if (await env.SITE_DATA.get(`clublead:${u}`)) good.push(u);
          if (good.length) ev.formLeads = good; else delete ev.formLeads;
        }
        if (body.publicForm !== undefined) { if (body.publicForm) ev.publicForm = true; else delete ev.publicForm; }
        await writeClubCal(env, all);
        if (calCap(ev) !== capBefore) ctx.waitUntil((async () => { await calSyncSpots(env, ev); await calPromote(env, ctx, ev.id); })()); // limit changed: rebuild the claims, and let waitlisted people in if there's room now
        return jsonResponse({ ok: true, event: view(ev) }, 200, corsHeaders);
      }
      if (!adminCalMatch[2] && M === "DELETE") { await writeClubCal(env, all.filter((e) => e.id !== ev.id)); await env.SITE_DATA.delete(calFormKey(ev.id)).catch(() => {}); await env.SITE_DATA.delete(`calhist:${ev.id}`).catch(() => {}); ctx.waitUntil(calSyncSpots(env, { id: ev.id, capacity: 0 }).catch(() => {})); return jsonResponse({ ok: true }, 200, corsHeaders); }
      if (adminCalMatch[4] === "edit-link" && M === "POST") { // make / replace / turn off the secret "anyone with this link can edit the page" link
        if (!canForm(ev)) return jsonResponse({ error: "Ask the main admin to give you access to this event's form" }, 403, corsHeaders);
        if (body.action === "off") delete ev.editToken; else ev.editToken = Array.from(crypto.getRandomValues(new Uint8Array(12)), (x) => x.toString(16).padStart(2, "0")).join("");
        await writeClubCal(env, all);
        return jsonResponse({ ok: true, editToken: ev.editToken || "" }, 200, corsHeaders);
      }
      if (adminCalMatch[4] === "restore" && M === "POST") { // undo the last edit made through the edit link
        if (!canForm(ev)) return jsonResponse({ error: "Ask the main admin to give you access to this event's form" }, 403, corsHeaders);
        const hk = `calhist:${ev.id}`; let h = []; try { h = JSON.parse((await env.SITE_DATA.get(hk)) || "[]"); } catch {}
        if (!h.length) return jsonResponse({ error: "Nothing to undo" }, 400, corsHeaders);
        const sn = h.shift(), keepPay = ev.form && ev.form.payment;
        Object.assign(ev, { title: sn.title, date: sn.date, time: sn.time, place: sn.place, mapUrl: sn.mapUrl, desc: sn.desc, rsvpBy: sn.rsvpBy });
        for (const k of ["blocks", "theme", "hosts"]) { if (sn[k]) ev[k] = sn[k]; else delete ev[k]; }
        if (sn.form) { ev.form = sn.form; if (keepPay) ev.form.payment = keepPay; else delete ev.form.payment; } else delete ev.form;
        ev.histN = h.length; await writeClubCal(env, all); await env.SITE_DATA.put(hk, JSON.stringify(h));
        return jsonResponse({ ok: true, event: view(ev) }, 200, corsHeaders);
      }
      if (adminCalMatch[4] === "message" && M === "POST") { // message everyone who's going (a few at a time: the page calls again with `offset` until `next` is null)
        const text = String(body.text || "").replace(/[\x00-\x1f\x7f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
        if (text.length < 3) return jsonResponse({ error: "Write the message first (3+ letters)" }, 400, corsHeaders);
        const aud = body.audience === "waitlist" ? ["waitlist"] : body.audience === "all" ? ["going", "waitlist"] : ["going"];
        const targets = (ev.rsvps || []).filter((r) => aud.includes(r.status)), members = targets.filter((r) => !String(r.id).startsWith("g:"));
        const off = Math.max(0, parseInt(body.offset, 10) || 0), batch = members.slice(off, off + 10);
        let reached = 0;
        for (const r of batch) { try { const res = await sendPushToUser(env, r.id, { title: cleanCalText(body.title, 60) || ev.title, body: text, url: `/#/form/${ev.slug || ev.id}`, cat: "events" }); if (res.sent > 0) reached++; } catch {} }
        return jsonResponse({ ok: true, total: members.length, noProfile: targets.length - members.length, reached, next: off + batch.length >= members.length ? null : off + batch.length }, 200, corsHeaders);
      }
      if (adminCalMatch[2] && M === "POST" && adminCalMatch[3] === "add") {
        // Mark someone as having come along (used for past events, also for people who never RSVPed).
        if (adminCalMatch[2] === "guest") { // someone WITHOUT a profile: just a name
          let gb = {}; try { gb = await request.json(); } catch {}
          const gname = sanitizePersonName(gb.name);
          if (gname.length < 2) return jsonResponse({ error: "Type their name (2+ letters)" }, 400, corsHeaders);
          ev.rsvps = ev.rsvps || [];
          const gid2 = `g:${crypto.randomUUID().slice(0, 12)}`;
          ev.rsvps.push({ id: gid2, name: gname, status: "going", at: Date.now(), added: true, guest: true });
          await calClaimSpot(env, ev, gid2, true);
          await writeClubCal(env, all);
          return jsonResponse({ ok: true, event: view(ev) }, 200, corsHeaders);
        }
        const u = await readUser(env, adminCalMatch[2]);
        if (!u) return jsonResponse({ error: "That member no longer exists" }, 404, corsHeaders);
        ev.rsvps = (ev.rsvps || []).filter((x) => x.id !== u.id);
        ev.rsvps.push({ id: u.id, name: sanitizePersonName(u.name) || "Member", status: "going", at: Date.now(), added: true });
        await calClaimSpot(env, ev, u.id, true);
        await writeClubCal(env, all);
        return jsonResponse({ ok: true, event: view(ev) }, 200, corsHeaders);
      }
      if (adminCalMatch[2] && M === "POST") {
        const r = (ev.rsvps || []).find((x) => x.id === adminCalMatch[2]);
        if (!r) return jsonResponse({ error: "Not on the list" }, 404, corsHeaders);
        if ((adminCalMatch[3] === "paid" || adminCalMatch[3] === "unpaid") && !canForm(ev)) return jsonResponse({ error: "Ask the main admin to give you access to this event's form" }, 403, corsHeaders);
        let freed = false;
        if (adminCalMatch[3] === "accept") { r.status = "going"; await calClaimSpot(env, ev, r.id, true); } // the organiser can always let someone in, even over the limit
        else if (adminCalMatch[3] === "paid") { r.paid = true; delete r.claimedPaid; }
        else if (adminCalMatch[3] === "unpaid") delete r.paid;
        else { ev.rsvps = ev.rsvps.filter((x) => x.id !== r.id); freed = true; }
        await writeClubCal(env, all);
        if (freed) ctx.waitUntil(calAfterRemoval(env, ctx, ev.id, r.id));
        return jsonResponse({ ok: true, event: view(ev) }, 200, corsHeaders);
      }
      return jsonResponse({ error: "Not found" }, 404, corsHeaders);
    }

    const adminEventsMatch = path.match(/^\/api\/admin\/club-events\/([^/]+)\/?$/);
    if (adminEventsMatch && request.method === "GET") {
      const clubId = decodeURIComponent(adminEventsMatch[1]);
      return jsonResponse({ events: await readClubEvents(env, clubId) }, 200, corsHeaders);
    }

    if (adminEventsMatch && request.method === "POST") {
      const clubId = decodeURIComponent(adminEventsMatch[1]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const title = String(body.title || "").trim().slice(0, 80);
      const desc = String(body.desc || "").trim().slice(0, 500);
      const startDate = String(body.startDate || "");
      const endDate = String(body.endDate || "");
      const startHour = Number(body.startHour);
      const endHour = Number(body.endHour);
      if (!title) return jsonResponse({ error: "Title is required" }, 400, corsHeaders);
      if (!isValidDateString(startDate) || !isValidDateString(endDate) || endDate < startDate) {
        return jsonResponse({ error: "Valid start and end dates are required (end on or after start)" }, 400, corsHeaders);
      }
      if (!Number.isInteger(startHour) || !Number.isInteger(endHour) || startHour < 0 || endHour > 24 || endHour <= startHour) {
        return jsonResponse({ error: "Start/end hour must be whole numbers, 0-24, with end after start" }, 400, corsHeaders);
      }
      const dates = dateRange(startDate, endDate);
      if (!dates.length) return jsonResponse({ error: "Date range is too long (max 31 days)" }, 400, corsHeaders);
      const event = { id: crypto.randomUUID(), title, desc, startDate, endDate, dates, startHour, endHour, createdAt: Date.now() };
      const events = await readClubEvents(env, clubId);
      events.push(event);
      await writeClubEvents(env, clubId, events);
      return jsonResponse(event, 201, corsHeaders);
    }

    const adminEventDeleteMatch = path.match(/^\/api\/admin\/club-events\/([^/]+)\/([^/]+)\/?$/);
    if (adminEventDeleteMatch && request.method === "DELETE") {
      const clubId = decodeURIComponent(adminEventDeleteMatch[1]);
      const eventId = decodeURIComponent(adminEventDeleteMatch[2]);
      const events = await readClubEvents(env, clubId);
      await writeClubEvents(env, clubId, events.filter(e => e.id !== eventId));
      await env.SITE_DATA.delete(clubEventResponsesKey(clubId, eventId)).catch(() => {});
      return jsonResponse({ ok: true }, 200, corsHeaders);
    }

    // Admin: create a brand-new calendar event — commits a new source file straight to GitHub
    if (path === "/api/admin/calendar-event" && request.method === "POST") {
      if (!env.GITHUB_TOKEN) return jsonResponse({ error: "Server misconfigured: GITHUB_TOKEN is not set" }, 500, corsHeaders);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const fields = body.fields;
      if (!fields || typeof fields !== "object") return jsonResponse({ error: "fields object is required" }, 400, corsHeaders);
      const title = String(fields.title || "").trim();
      if (!title) return jsonResponse({ error: "Title is required" }, 400, corsHeaders);
      if (!CALENDAR_SECTIONS.includes(fields.section)) return jsonResponse({ error: "A valid Calendar tab is required" }, 400, corsHeaders);
      if (!isValidDateString(fields.eventDate)) return jsonResponse({ error: "A valid Event date is required" }, 400, corsHeaders);
      if (!fields.virtual && !String(fields.location || "").trim()) return jsonResponse({ error: "A location is required (or mark the event as virtual)" }, 400, corsHeaders);

      const baseSlug = slugify(title);
      if (!CALENDAR_ID_RE.test(baseSlug)) return jsonResponse({ error: "Could not derive a valid id from the title" }, 400, corsHeaders);
      let finalSlug = baseSlug;
      for (let n = 2; await githubGetFile(env, calendarFilePath(finalSlug)); n++) {
        if (n > 50) return jsonResponse({ error: "Could not find a unique id for this title" }, 500, corsHeaders);
        finalSlug = `${baseSlug}-${n}`;
      }

      const { id: _drop, ...content } = fields;
      const commitMessage = `Create "${title}" via site admin editor`;
      const res = await githubPutFile(env, calendarFilePath(finalSlug), content, undefined, commitMessage);
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        return jsonResponse({ error: "GitHub commit failed", detail }, 502, corsHeaders);
      }
      return jsonResponse({ ok: true, id: finalSlug, content }, 201, corsHeaders);
    }

    // Admin: read/edit a calendar event's real source file — commits straight to GitHub
    const adminCalEventMatch = path.match(/^\/api\/admin\/calendar-event\/([^/]+)\/?$/);
    if (adminCalEventMatch && (request.method === "GET" || request.method === "PUT" || request.method === "DELETE")) {
      if (!env.GITHUB_TOKEN) return jsonResponse({ error: "Server misconfigured: GITHUB_TOKEN is not set" }, 500, corsHeaders);
      const id = decodeURIComponent(adminCalEventMatch[1]);
      if (!CALENDAR_ID_RE.test(id)) return jsonResponse({ error: "Invalid event id" }, 400, corsHeaders);

      if (request.method === "GET") {
        const resolved = await resolveCalendarFile(env, id);
        if (!resolved) return jsonResponse({ error: "Event source file not found" }, 404, corsHeaders);
        return jsonResponse(resolved.file.content, 200, corsHeaders);
      }

      if (request.method === "DELETE") {
        const resolved = await resolveCalendarFile(env, id);
        if (!resolved) return jsonResponse({ error: "Event source file not found" }, 404, corsHeaders);
        const { file, path: filePath } = resolved;
        const commitMessage = `Delete "${file.content.title || id}" via site admin editor`;
        const res = await githubDeleteFile(env, filePath, file.sha, commitMessage);
        if (!res.ok) {
          const detail = await res.text().catch(() => "");
          return jsonResponse({ error: "GitHub delete failed", detail }, 502, corsHeaders);
        }
        return jsonResponse({ ok: true, deleted: id, path: filePath }, 200, corsHeaders);
      }

      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!body.fields || typeof body.fields !== "object") return jsonResponse({ error: "fields object is required" }, 400, corsHeaders);
      const resolved = await resolveCalendarFile(env, id);
      if (!resolved) return jsonResponse({ error: "Event source file not found" }, 404, corsHeaders);
      const { file, path: filePath } = resolved;
      const updated = { ...file.content, ...body.fields };
      // A few pre-migration files still carry a legacy `category` field (e.g.
      // "functions") left over from before `section` became authoritative. If left
      // in place it silently overrides any reclassification in the site's tagClass()
      // logic, so strip it on every edit going through this endpoint.
      delete updated.category;
      const commitMessage = `Edit "${updated.title || id}" via site admin editor`;
      const res = await githubPutFile(env, filePath, updated, file.sha, commitMessage);
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        return jsonResponse({ error: "GitHub commit failed", detail }, 502, corsHeaders);
      }
      return jsonResponse({ ok: true, content: updated }, 200, corsHeaders);
    }

    // Admin: create a brand-new Resources/Small-Business listing — same GitHub pattern as calendar events
    if (path === "/api/admin/resource" && request.method === "POST") {
      if (!env.GITHUB_TOKEN) return jsonResponse({ error: "Server misconfigured: GITHUB_TOKEN is not set" }, 500, corsHeaders);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const fields = body.fields;
      if (!fields || typeof fields !== "object") return jsonResponse({ error: "fields object is required" }, 400, corsHeaders);
      const title = String(fields.title || "").trim();
      if (!title) return jsonResponse({ error: "Title is required" }, 400, corsHeaders);
      if (!RESOURCE_CATEGORIES.includes(fields.category)) return jsonResponse({ error: "A valid category is required" }, 400, corsHeaders);
      if (!String(fields.ownedBy || "").trim()) return jsonResponse({ error: "Ownership note is required" }, 400, corsHeaders);

      const baseSlug = slugify(title);
      if (!CALENDAR_ID_RE.test(baseSlug)) return jsonResponse({ error: "Could not derive a valid id from the title" }, 400, corsHeaders);
      let finalSlug = baseSlug;
      for (let n = 2; await githubGetFile(env, resourceFilePath(finalSlug)); n++) {
        if (n > 50) return jsonResponse({ error: "Could not find a unique id for this title" }, 500, corsHeaders);
        finalSlug = `${baseSlug}-${n}`;
      }

      const { id: _drop, ...content } = fields;
      if (content.image !== undefined) content.image = sanitizePhoto(content.image);
      const commitMessage = `Create "${title}" via site admin editor`;
      const res = await githubPutFile(env, resourceFilePath(finalSlug), content, undefined, commitMessage);
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        return jsonResponse({ error: "GitHub commit failed", detail }, 502, corsHeaders);
      }
      return jsonResponse({ ok: true, id: finalSlug, content }, 201, corsHeaders);
    }

    // Admin: read/edit a Resources/Small-Business listing
    const adminResourceMatch = path.match(/^\/api\/admin\/resource\/([^/]+)\/?$/);
    if (adminResourceMatch && (request.method === "GET" || request.method === "PUT")) {
      if (!env.GITHUB_TOKEN) return jsonResponse({ error: "Server misconfigured: GITHUB_TOKEN is not set" }, 500, corsHeaders);
      const id = decodeURIComponent(adminResourceMatch[1]);
      if (!CALENDAR_ID_RE.test(id)) return jsonResponse({ error: "Invalid resource id" }, 400, corsHeaders);

      if (request.method === "GET") {
        const resolved = await resolveResourceFile(env, id);
        if (!resolved) return jsonResponse({ error: "Resource source file not found" }, 404, corsHeaders);
        return jsonResponse(resolved.file.content, 200, corsHeaders);
      }

      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!body.fields || typeof body.fields !== "object") return jsonResponse({ error: "fields object is required" }, 400, corsHeaders);
      const resolved = await resolveResourceFile(env, id);
      if (!resolved) return jsonResponse({ error: "Resource source file not found" }, 404, corsHeaders);
      const { file, path: filePath } = resolved;
      const fields = { ...body.fields };
      if (fields.image !== undefined) fields.image = sanitizePhoto(fields.image);
      const updated = { ...file.content, ...fields };
      const commitMessage = `Edit "${updated.title || id}" via site admin editor`;
      const res = await githubPutFile(env, filePath, updated, file.sha, commitMessage);
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        return jsonResponse({ error: "GitHub commit failed", detail }, 502, corsHeaders);
      }
      return jsonResponse({ ok: true, content: updated }, 200, corsHeaders);
    }

    // Admin: edit sitetext.json (one fixed file — page copy, home-tile text, and now
    // the About/Rules page content) — same GitHub-commit pattern, no slug/id needed.
    if (path === "/api/admin/sitetext" && (request.method === "GET" || request.method === "PUT")) {
      if (!env.GITHUB_TOKEN) return jsonResponse({ error: "Server misconfigured: GITHUB_TOKEN is not set" }, 500, corsHeaders);
      const filePath = "data/sitetext.json";

      if (request.method === "GET") {
        const file = await githubGetFile(env, filePath);
        if (!file) return jsonResponse({ error: "sitetext.json not found" }, 404, corsHeaders);
        return jsonResponse(file.content, 200, corsHeaders);
      }

      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!body.fields || typeof body.fields !== "object") return jsonResponse({ error: "fields object is required" }, 400, corsHeaders);
      const file = await githubGetFile(env, filePath);
      if (!file) return jsonResponse({ error: "sitetext.json not found" }, 404, corsHeaders);
      const updated = { ...file.content, ...body.fields };
      const res = await githubPutFile(env, filePath, updated, file.sha, "Edit page text via site admin editor");
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        return jsonResponse({ error: "GitHub commit failed", detail }, 502, corsHeaders);
      }
      return jsonResponse({ ok: true, content: updated }, 200, corsHeaders);
    }

    // Admin: the Clubs directory (data/clubs.json - one array file, not per-entry
    // like calendar/resources, since there are only a handful and low churn).
    const CLUBS_FILE_PATH = "data/clubs.json";
    if (path === "/api/admin/clubs" && (request.method === "GET" || request.method === "POST")) {
      if (!env.GITHUB_TOKEN) return jsonResponse({ error: "Server misconfigured: GITHUB_TOKEN is not set" }, 500, corsHeaders);
      const file = await githubGetFile(env, CLUBS_FILE_PATH);
      if (!file) return jsonResponse({ error: "clubs.json not found" }, 404, corsHeaders);
      // The file on disk is { items: [...] }, not a bare array.
      const clubs = Array.isArray(file.content?.items) ? file.content.items : (Array.isArray(file.content) ? file.content : []);

      if (request.method === "GET") return jsonResponse({ clubs }, 200, corsHeaders);

      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const fields = body.fields;
      if (!fields || typeof fields !== "object") return jsonResponse({ error: "fields object is required" }, 400, corsHeaders);
      const title = String(fields.title || "").trim();
      if (!title) return jsonResponse({ error: "Title is required" }, 400, corsHeaders);
      const desc = String(fields.desc || "").trim();
      if (!desc) return jsonResponse({ error: "Description is required" }, 400, corsHeaders);

      const shortSlug = slugify(title);
      const baseSlug = `club-${shortSlug}`;
      let finalId = baseSlug;
      let finalSlug = shortSlug;
      for (let n = 2; clubs.some((c) => c.id === finalId || c.slug === finalSlug); n++) {
        if (n > 50) return jsonResponse({ error: "Could not find a unique id for this title" }, 500, corsHeaders);
        finalId = `${baseSlug}-${n}`;
        finalSlug = `${shortSlug}-${n}`;
      }

      const newClub = { id: finalId, slug: finalSlug, title, desc };
      const emoji = String(fields.emoji || "").trim().slice(0, 8);
      if (emoji) newClub.emoji = emoji;
      const colour = sanitizeColour(fields.colour);
      if (colour) newClub.colour = colour;
      const textColour = sanitizeColour(fields.textColour);
      if (textColour) newClub.textColour = textColour;
      if (typeof fields.logo === "string" && fields.logo.startsWith("data:")) {
        const photo = sanitizePhoto(fields.logo);
        if (fields.logo && !photo) return jsonResponse({ error: "Logo image is too large or not a supported format" }, 400, corsHeaders);
        if (photo) newClub.logo = photo;
      }
      if (String(fields.signup || "").trim()) newClub.signup = String(fields.signup).trim();

      const updated = [...clubs, newClub];
      const res = await githubPutFile(env, CLUBS_FILE_PATH, { items: updated }, file.sha, `Add club "${title}" via site admin editor`);
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        return jsonResponse({ error: "GitHub commit failed", detail }, 502, corsHeaders);
      }
      await writeClubRoster(env, updated);
      await setClubDeleted(env, finalId, false).catch(() => {});
      return jsonResponse({ ok: true, id: finalId, club: newClub }, 201, corsHeaders);
    }

    const adminClubMatch = path.match(/^\/api\/admin\/clubs\/([^/]+)\/?$/);
    if (adminClubMatch && (request.method === "PUT" || request.method === "DELETE")) {
      if (!env.GITHUB_TOKEN) return jsonResponse({ error: "Server misconfigured: GITHUB_TOKEN is not set" }, 500, corsHeaders);
      const id = decodeURIComponent(adminClubMatch[1]);
      const file = await githubGetFile(env, CLUBS_FILE_PATH);
      if (!file) return jsonResponse({ error: "clubs.json not found" }, 404, corsHeaders);
      // The file on disk is { items: [...] }, not a bare array.
      const clubs = Array.isArray(file.content?.items) ? file.content.items : (Array.isArray(file.content) ? file.content : []);
      const idx = clubs.findIndex((c) => c.id === id);
      if (request.method === "DELETE") {
        // Remember the deletion FIRST so the file sync can't bring the club back, even while the old clubs.json is still deployed.
        await setClubDeleted(env, id, true);
        if (idx !== -1) {
          const removed = clubs[idx];
          const updated = clubs.filter((c) => c.id !== id);
          const res = await githubPutFile(env, CLUBS_FILE_PATH, { items: updated }, file.sha, `Remove club "${removed.title || id}" via site admin editor`);
          if (!res.ok) {
            const detail = await res.text().catch(() => "");
            return jsonResponse({ error: "GitHub commit failed", detail }, 502, corsHeaders);
          }
        }
        const rosterNow = await env.SITE_DATA.get(CLUB_ROSTER_KV_KEY).then((r) => { try { const a = JSON.parse(r); return Array.isArray(a) ? a : []; } catch { return []; } });
        await writeClubRoster(env, rosterNow.filter((c) => c.id !== id));
        return jsonResponse({ ok: true, deleted: id }, 200, corsHeaders);
      }
      if (idx === -1) return jsonResponse({ error: "Club not found" }, 404, corsHeaders);

      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!body.fields || typeof body.fields !== "object") return jsonResponse({ error: "fields object is required" }, 400, corsHeaders);
      const fields = { ...body.fields };
      if (fields.signup !== undefined) { const v = String(fields.signup || "").trim().slice(0, 500); if (v && !/^https:\/\//i.test(v)) return jsonResponse({ error: "The link must start with https://" }, 400, corsHeaders); fields.signup = v; }
      delete fields.id; // immutable once created
      delete fields.slug; // immutable once created — shared links point at it
      if (fields.emoji !== undefined) fields.emoji = String(fields.emoji || "").trim().slice(0, 8);
      if (fields.colour !== undefined) {
        const colour = sanitizeColour(fields.colour);
        if (fields.colour && !colour) return jsonResponse({ error: "Colour must look like #rrggbb" }, 400, corsHeaders);
        fields.colour = colour;
      }
      if (fields.textColour !== undefined) {
        const textColour = sanitizeColour(fields.textColour);
        if (fields.textColour && !textColour) return jsonResponse({ error: "Text colour must look like #rrggbb" }, 400, corsHeaders);
        fields.textColour = textColour;
      }
      // Only touch logo when the submitted value is an actual new upload (a
      // data: URL) - an edit form re-sending the existing plain-path value
      // unchanged must never silently null it out.
      if (fields.logo !== undefined) {
        if (typeof fields.logo === "string" && fields.logo.startsWith("data:")) {
          const photo = sanitizePhoto(fields.logo);
          if (!photo) return jsonResponse({ error: "Logo image is too large or not a supported format" }, 400, corsHeaders);
          fields.logo = photo;
        } else {
          delete fields.logo;
        }
      }
      const updatedClub = { ...clubs[idx], ...fields };
      const updated = clubs.slice();
      updated[idx] = updatedClub;
      const res = await githubPutFile(env, CLUBS_FILE_PATH, { items: updated }, file.sha, `Edit club "${updatedClub.title || id}" via site admin editor`);
      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        return jsonResponse({ error: "GitHub commit failed", detail }, 502, corsHeaders);
      }
      await writeClubRoster(env, updated);
      return jsonResponse({ ok: true, club: updatedClub }, 200, corsHeaders);
    }

    if (path.startsWith("/api/data/")) {
      const key = path.replace("/api/data/", "");

      if (request.method === "GET") {
        const value = await env.SITE_DATA.get(key);
        return new Response(value || "null", {
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      }

      if (request.method === "POST") {
        const body = await request.text();
        await env.SITE_DATA.put(key, body);
        return new Response("OK", { headers: corsHeaders });
      }
    }

    // ---- Editor UI ----

    if (path === "/editor" || path === "/editor/") {
      return new Response(`<!DOCTYPE html>
<html>
<head>
  <title>4DASISTAS Editor</title>
  <style>
    body { font-family: system-ui; max-width: 800px; margin: 40px auto; padding: 20px; }
    textarea { width: 100%; height: 400px; font-family: monospace; }
    button { padding: 10px 20px; background: #373d3b; color: white; border: none; cursor: pointer; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    a { color: #373d3b; text-decoration: none; }
  </style>
</head>
<body>
  <div class="header">
    <h1>4DASISTAS Tab Editor</h1>
    <a href="/logout">Logout</a>
  </div>
  <p>Select a data key to edit below.</p>
  <div style="margin-bottom: 20px;">
    <select id="keySelect" onchange="loadKey()">
      <option value="">-- Select data key --</option>
      <option value="sports">Sports</option>
      <option value="gatherings">Gatherings</option>
      <option value="dayactivities">Day Activities</option>
      <option value="trips">Trips</option>
      <option value="clubs">Clubs</option>
      <option value="resources">Resources</option>
      <option value="smallbusinesses">Small Businesses</option>
      <option value="mosquegatherings">Mosque Gatherings</option>
    </select>
  </div>
  <textarea id="editor" placeholder="Select a key above to load data..."></textarea>
  <br><br>
  <button onclick="save()">Save</button>
  <p id="status" style="margin-top: 10px;"></p>
  <script>
    async function loadKey() {
      const key = document.getElementById('keySelect').value;
      if (!key) return;
      const res = await fetch('/api/data/' + key);
      document.getElementById('editor').value = await res.text();
      document.getElementById('status').textContent = 'Loaded: ' + key;
    }
    async function save() {
      const key = document.getElementById('keySelect').value;
      if (!key) { alert('Select a key first'); return; }
      const data = document.getElementById('editor').value;
      const res = await fetch('/api/data/' + key, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: data
      });
      if (res.ok) {
        document.getElementById('status').textContent = 'Saved!';
      } else {
        document.getElementById('status').textContent = 'Error: ' + res.status;
      }
    }
  </script>

  <hr style="margin: 40px 0;">
  <h2>Club Members Schedule — Admin</h2>
  <p style="font-size: 13px; color: #666;">View every club's member list and reset a member's PIN if they lose it (they'll need the new PIN to sign back in).</p>
  <div id="clubMembersPanel">Loading…</div>
  <script>
    function escapeCmAdmin(s) {
      const d = document.createElement('div');
      d.textContent = s == null ? '' : String(s);
      return d.innerHTML;
    }
    async function loadClubMembers() {
      const panel = document.getElementById('clubMembersPanel');
      const res = await fetch('/api/admin/club-members', { credentials: 'include' });
      if (!res.ok) { panel.textContent = 'Failed to load (' + res.status + ')'; return; }
      const data = await res.json();
      const clubIds = Object.keys(data).filter(id => data[id].length);
      if (!clubIds.length) { panel.textContent = 'No club members yet.'; return; }
      panel.innerHTML = clubIds.map(clubId => {
        const members = data[clubId];
        return '<h3>' + escapeCmAdmin(clubId) + '</h3><table style="width:100%;border-collapse:collapse;margin-bottom:20px;">' +
          members.map(m => '<tr style="border-bottom:1px solid #ddd;"><td style="padding:6px;">' +
            (m.photo ? '<img src="' + escapeCmAdmin(m.photo) + '" style="width:28px;height:28px;border-radius:50%;object-fit:cover;vertical-align:middle;margin-right:8px;">' : '') +
            escapeCmAdmin(m.name) + ' <span style="color:#888;">@' + escapeCmAdmin(m.username || '?') + '</span></td>' +
            '<td style="padding:6px;text-align:right;"><button onclick="resetClubMemberPin(\\'' + clubId + '\\',\\'' + m.id + '\\')">Reset PIN</button> ' +
            '<button onclick="removeClubMember(\\'' + clubId + '\\',\\'' + m.id + '\\')" style="background:#c00;">Remove</button></td></tr>').join('') +
          '</table>';
      }).join('');
    }
    async function resetClubMemberPin(clubId, memberId) {
      const res = await fetch('/api/admin/club-members/' + encodeURIComponent(clubId) + '/' + encodeURIComponent(memberId) + '/reset-pin', { method: 'POST', credentials: 'include' });
      const data = await res.json();
      if (res.ok) alert('New PIN: ' + data.pin + '\\n\\nTell this member their new PIN so they can sign back in.');
      else alert('Error: ' + (data.error || res.status));
    }
    async function removeClubMember(clubId, memberId) {
      if (!confirm('Remove this member? This cannot be undone.')) return;
      const res = await fetch('/api/admin/club-members/' + encodeURIComponent(clubId) + '/' + encodeURIComponent(memberId), { method: 'DELETE', credentials: 'include' });
      if (res.ok) loadClubMembers(); else alert('Error: ' + res.status);
    }
    loadClubMembers();
  </script>
</body>
</html>`, {
        headers: { "Content-Type": "text/html", ...corsHeaders },
      });
    }

    // ---- Default ----

    // The app shell (index.html, and the service worker / manifest that control it) must never be cached
    // at Cloudflare's edge. It kept coming back "cf-cache-status: HIT" on a stale copy after a deploy, so a
    // link/routing change that already shipped could still look broken for a while depending which edge
    // node a visitor hit. Everything else (images, /data/*.json, fonts) keeps its normal caching.
    if (env.ASSETS) {
      const res = await env.ASSETS.fetch(request);
      const isShell = path === "/" || path === "/index.html" || path === "/service-worker.js" || path === "/manifest.webmanifest";
      if (isShell) {
        const fresh = new Response(res.body, res);
        fresh.headers.set("Cache-Control", "no-store, must-revalidate");
        return fresh;
      }
      return res;
    }
    return new Response("4DASISTAS Worker — use /api/data/:key, /editor, /login, or /logout", {
      headers: { "Content-Type": "text/plain", ...corsHeaders },
    });
  },

  async scheduled(controller, env, ctx) {
    if (controller.cron === "23 * * * *") { // hourly: event reminders (a few people per run), then refresh everyone who gets steps from Google Health, so the leaderboard is current even if they don't open the app
      ctx.waitUntil(calSendReminders(env, ctx).catch((e) => console.log("event reminders failed", String(e && e.message))));
      ctx.waitUntil((async () => { try { if (!(await ghEnsure(env)) || !(await stepsEnsure(env))) return; const rows = (await env.DB.prepare("SELECT g.user_id AS u FROM gh_tokens g JOIN step_sources s ON s.user_id = g.user_id AND s.source = 'googlehealth'").all()).results || []; for (const r of rows.slice(0, 40)) { try { await ghSync(env, r.u); } catch (e) { console.log("gh hourly", String(e && e.message)); } } _stepsPublicMemo = { at: 0, data: null }; } catch (e) { console.log("gh hourly failed", String(e && e.message)); } })());
      return;
    }
    ctx.waitUntil((async () => { try { if (!(await env.SITE_DATA.get("phoneidx:built"))) await rebuildPhoneIndex(env); if (await seenEnsure(env)) await env.DB.prepare("DELETE FROM rate_limits WHERE exp < ?").bind(Date.now()).run(); } catch (e) { console.log("maintenance failed", e && e.message); } })());
    ctx.waitUntil((async () => { try { const claimed = await claimBackupSlot(env); console.log("daily backup slot", claimed ? "claimed — sending" : "already taken — skipping"); if (claimed) await sendBackupEmail(env, "Daily backup"); } catch (e) { console.error("Backup email failed", String(e)); } })()); // once a day; independent of the digest below
    if (!env.RESEND_API_KEY) return;
    let subscribers = JSON.parse((await env.SITE_DATA.get(SUBSCRIBER_INDEX_KEY)) || "[]");
    { const seenE = new Set(); subscribers = subscribers.filter((x) => x && x.email && !x.paused && !seenE.has(x.email) && seenE.add(x.email)); } // one email per address, none to paused ones
    if (!subscribers.length) return;
    const { dateString, events } = await readTodayEvents(env);
    if (!events.length) return;
    if (!(await claimBackupSlot(env, "digest"))) { console.log("daily digest already sent today — skipping"); return; } // the cron fired more than once (that's why the digest arrived 4 times)
    const origin = env.SITE_ORIGIN || "https://4dasistas.ca";
    const subject = `What's on today at 4DASISTAS — ${dateString}`;
    for (const subscriber of subscribers) {
      const unsubscribeUrl = `${origin}/api/unsubscribe?token=${encodeURIComponent(subscriber.token)}`, manageUrl = `${origin}/api/manage-subscription?token=${encodeURIComponent(subscriber.token)}`;
      ctx.waitUntil(postResend(env, { from: env.FROM_EMAIL || "4DASISTAS <updates@4dasistas.ca>", to: [subscriber.email], subject, html: digestEmailHtml(env, dateString, events, unsubscribeUrl, manageUrl) }));
    }
  },
};
