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

const sanitizeUsername = (input) => {
  const u = String(input || "").trim().toLowerCase();
  return /^[a-z0-9_]{3,20}$/.test(u) ? u : null;
};

// Clubs people can join through the public Sign Up form (mirrors FALL_SIGNUP_CLUBS in index.html).
const SIGNUP_CLUB_IDS = new Set(["club-activegaming", "club-adrenaline", "club-theater", "club-cuisine", "club-artscrafts", "club-retreats", "club-adhd"]);
const SIGNUP_MAX_PER_IP_PER_HOUR = 10;
const SIGNUP_MAX_PER_DAY = 100;

// ---- Global member identity: one person, one username, can belong to several clubs ----
const userKey = (userId) => `user:${userId}`;

const readUser = async (env, userId) => {
  const raw = await env.SITE_DATA.get(userKey(userId));
  return raw ? JSON.parse(raw) : null;
};

const writeUser = async (env, user) => {
  await env.SITE_DATA.put(userKey(user.id), JSON.stringify(user));
};

const deleteUser = async (env, userId) => {
  await env.SITE_DATA.delete(userKey(userId));
};

const visibleWaitlist = (user, clubs) => (Array.isArray(user.waitlist) ? user.waitlist : []).filter((id) => !clubs.includes(id));
const publicUser = (u) => ({ id: u.id, name: u.name, username: u.username, photo: u.photo || null });

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

const allClubIdsContaining = async (env, userId) => {
  const list = await env.SITE_DATA.list({ prefix: "clubmembers:" });
  const out = [];
  for (const key of list.keys) {
    const clubId = key.name.replace("clubmembers:", "");
    const ids = await readClubMemberIds(env, clubId);
    if (ids.includes(userId)) out.push(clubId);
  }
  return out;
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
const RESOURCE_CATEGORIES = ["cafes", "shops", "restaurants", "beautycare", "mentalhealth", "bakeries", "legal", "communityorg", "fitness"];

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

const eventIsOnDate = (item, dateString) => {
  if (item.calDate === dateString || item.eventDate === dateString) return true;
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
    const response = await fetch(`${origin}/data/${file}.json`, { cf: { cacheTtl: 60 } });
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
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/subscribe" && request.method === "POST") {
      let email;
      try { email = String((await request.json()).email || "").trim().toLowerCase(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonResponse({ error: "Valid email required" }, 400, corsHeaders);
      const index = JSON.parse((await env.SITE_DATA.get(SUBSCRIBER_INDEX_KEY)) || "[]");
      const existing = index.find(subscriber => subscriber.email === email);
      if (existing) return jsonResponse({ ok: true }, 200, corsHeaders);
      const token = crypto.randomUUID();
      index.push({ email, token, createdAt: Date.now() });
      await env.SITE_DATA.put(SUBSCRIBER_INDEX_KEY, JSON.stringify(index));
      return jsonResponse({ ok: true }, 201, corsHeaders);
    }

    if (path === "/api/unsubscribe" && request.method === "GET") {
      const token = url.searchParams.get("token");
      const index = JSON.parse((await env.SITE_DATA.get(SUBSCRIBER_INDEX_KEY)) || "[]");
      const next = index.filter(subscriber => subscriber.token !== token);
      await env.SITE_DATA.put(SUBSCRIBER_INDEX_KEY, JSON.stringify(next));
      return new Response("You have been unsubscribed from the daily 4DASISTAS list.", { headers: { "Content-Type": "text/plain", ...corsHeaders } });
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
      const username = sanitizeUsername(body.username);
      const pin = String(body.pin || "").trim();
      if (!username || !pin) return jsonResponse({ error: "Username and PIN are required" }, 400, corsHeaders);
      const userId = await findUserIdByUsername(env, username);
      const user = userId ? await readUser(env, userId) : null;
      if (!user || user.pinHash !== await sha256Hex(pin)) {
        return jsonResponse({ error: "Username or PIN is incorrect" }, 401, corsHeaders);
      }
      const token = await createMemberSession(env, user.id);
      const clubs = await allClubIdsContaining(env, user.id);
      return jsonResponse({ ...publicUser(user), clubs, waitlist: visibleWaitlist(user, clubs), token }, 200, corsHeaders);
    }

    // Public self-signup (Sign Up form): creates the account, joins the chosen club, and signs them in.
    if (path === "/api/signup" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const name = String(body.name || "").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 60);
      const username = sanitizeUsername(body.username);
      const pin = String(body.pin || "").trim();
      const clubId = String(body.clubId || "");
      if (!name) return jsonResponse({ error: "Please enter your name" }, 400, corsHeaders);
      if (!username) return jsonResponse({ error: "Username must be 3-20 characters: letters, numbers and underscore only" }, 400, corsHeaders);
      if (!/^\d{4}$/.test(pin)) return jsonResponse({ error: "PIN must be exactly 4 digits" }, 400, corsHeaders);
      if (!SIGNUP_CLUB_IDS.has(clubId)) return jsonResponse({ error: "Please pick a club from the list" }, 400, corsHeaders);

      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const ipKey = `signuprate:${ip}:${Math.floor(Date.now() / 3600000)}`;
      const dayKey = `signupday:${new Date().toISOString().slice(0, 10)}`;
      const [ipCount, dayCount] = await Promise.all([env.SITE_DATA.get(ipKey), env.SITE_DATA.get(dayKey)]);
      if (Number(ipCount || 0) >= SIGNUP_MAX_PER_IP_PER_HOUR) return jsonResponse({ error: "Too many sign-ups from this connection — please try again in an hour" }, 429, corsHeaders);
      if (Number(dayCount || 0) >= SIGNUP_MAX_PER_DAY) return jsonResponse({ error: "Sign-ups are very busy right now — please message us on Instagram" }, 429, corsHeaders);

      if (await findUserIdByUsername(env, username)) return jsonResponse({ error: "That username is taken — try another (add a number or your last initial)" }, 409, corsHeaders);

      const waitlist = [...new Set((Array.isArray(body.waitlist) ? body.waitlist : []).map(String))].filter((id) => SIGNUP_CLUB_IDS.has(id) && id !== clubId).slice(0, 2);
      const user = { id: crypto.randomUUID(), name, username, pinHash: await sha256Hex(pin), photo: null, waitlist, createdAt: Date.now() };
      await writeUser(env, user);
      await reserveUsername(env, username, user.id);
      const memberIds = await readClubMemberIds(env, clubId);
      memberIds.push(user.id);
      await writeClubMemberIds(env, clubId, memberIds);
      await Promise.all([
        env.SITE_DATA.put(ipKey, String(Number(ipCount || 0) + 1), { expirationTtl: 3700 }),
        env.SITE_DATA.put(dayKey, String(Number(dayCount || 0) + 1), { expirationTtl: 90000 }),
      ]);
      const token = await createMemberSession(env, user.id);
      const clubs = await allClubIdsContaining(env, user.id);
      return jsonResponse({ ...publicUser(user), clubs, waitlist: visibleWaitlist(user, clubs), token }, 201, corsHeaders);
    }

    if (cmMembersMatch && request.method === "GET") {
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

    if (path === "/api/admin/session" && request.method === "GET") {
      const loggedIn = await isValidSession(getSessionToken(request));
      return jsonResponse({ loggedIn }, 200, corsHeaders);
    }

    // ---- Auth guard for editor and writes ----

    const requiresAuth = path === "/editor" || (path.startsWith("/api/data/") && request.method === "POST") || path.startsWith("/api/admin/club-members") || path.startsWith("/api/admin/club-events") || path.startsWith("/api/admin/users/") || path.startsWith("/api/admin/calendar-event") || path.startsWith("/api/admin/resource") || path.startsWith("/api/admin/sitetext");

    if (requiresAuth) {
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

    // Admin: manage club members / reset PINs (session-cookie gated above)
    if (path === "/api/admin/club-members" && request.method === "GET") {
      const list = await env.SITE_DATA.list({ prefix: "clubmembers:" });
      const out = {};
      for (const key of list.keys) {
        const clubId = key.name.replace("clubmembers:", "");
        out[clubId] = (await resolveClubMembers(env, clubId)).map(publicUser);
      }
      return jsonResponse(out, 200, corsHeaders);
    }

    const adminClubMembersCreateMatch = path.match(/^\/api\/admin\/club-members\/([^/]+)\/?$/);
    if (adminClubMembersCreateMatch && request.method === "POST") {
      const clubId = decodeURIComponent(adminClubMembersCreateMatch[1]);
      let body;
      try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid request" }, 400, corsHeaders); }
      const username = sanitizeUsername(body.username);
      if (!username) return jsonResponse({ error: "Username must be 3-20 characters: letters, numbers, underscore only" }, 400, corsHeaders);

      const existingUserId = await findUserIdByUsername(env, username);
      const memberIds = await readClubMemberIds(env, clubId);

      if (existingUserId) {
        // This person already has an account elsewhere — just add them to this club too.
        const user = await readUser(env, existingUserId);
        if (!user) return jsonResponse({ error: "That username exists but its record is missing — contact support" }, 500, corsHeaders);
        if (!memberIds.includes(existingUserId)) {
          memberIds.push(existingUserId);
          await writeClubMemberIds(env, clubId, memberIds);
        }
        return jsonResponse({ id: user.id, name: user.name, username: user.username, addedExisting: true }, 200, corsHeaders);
      }

      const name = String(body.name || "").trim().slice(0, 60);
      if (!name) return jsonResponse({ error: "Name is required" }, 400, corsHeaders);
      let pin = String(body.pin || "").trim();
      if (pin && !/^\d{4}$/.test(pin)) return jsonResponse({ error: "PIN must be exactly 4 digits" }, 400, corsHeaders);
      if (!pin) pin = randomPin();
      const user = { id: crypto.randomUUID(), name, username, pinHash: await sha256Hex(pin), photo: null, createdAt: Date.now() };
      await writeUser(env, user);
      await reserveUsername(env, username, user.id);
      memberIds.push(user.id);
      await writeClubMemberIds(env, clubId, memberIds);
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
        if (!username) return jsonResponse({ error: "Username must be 3-20 characters: letters, numbers, underscore only" }, 400, corsHeaders);
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

    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("4DASISTAS Worker — use /api/data/:key, /editor, /login, or /logout", {
      headers: { "Content-Type": "text/plain", ...corsHeaders },
    });
  },

  async scheduled(controller, env, ctx) {
    if (!env.RESEND_API_KEY) return;
    const subscribers = JSON.parse((await env.SITE_DATA.get(SUBSCRIBER_INDEX_KEY)) || "[]");
    if (!subscribers.length) return;
    const { dateString, events } = await readTodayEvents(env);
    if (!events.length) return;
    const origin = env.SITE_ORIGIN || "https://4dasistas.ca";
    const list = events.map(item => `<li><strong>${escapeHtml(item.title)}</strong><br>${escapeHtml(item.date || "Today")} · ${escapeHtml(item.location || "Location TBA")}</li>`).join("");
    const subject = `What's on today at 4DASISTAS — ${dateString}`;
    for (const subscriber of subscribers) {
      const unsubscribeUrl = `${origin}/api/unsubscribe?token=${encodeURIComponent(subscriber.token)}`;
      ctx.waitUntil(fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          from: env.FROM_EMAIL || "4DASISTAS <updates@4dasistas.ca>",
          to: [subscriber.email],
          subject,
          html: `<div style="font-family:Arial,sans-serif;max-width:560px;color:#373d3b"><h1 style="color:#caaacd">WHAT'S ON TODAY</h1><p>${escapeHtml(dateString)}</p><ul>${list}</ul><p style="color:#776867;font-size:12px">You are receiving this because you subscribed to the 4DASISTAS daily list. <a href="${unsubscribeUrl}">Unsubscribe</a></p></div>`,
        }),
      }));
    }
  },
};
