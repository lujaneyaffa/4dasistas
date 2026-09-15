// API for Lujane's painting shop. Static pages (public/) are served
// automatically by the [assets] binding in wrangler.toml; this worker
// only ever sees requests under /api/*.
//
// Storage is entirely Cloudflare KV (binding ART_DATA) - no external
// database needed:
//   painting:<id>        JSON painting record
//   paintings:index       JSON array of painting ids, newest first
//   bids:<paintingId>     JSON array of bids for that painting
//   image:<imageId>       raw image bytes (metadata: {contentType})
//   session:<token>       "1", expires after 7 days (admin login)

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (!pathname.startsWith("/api/")) {
      return new Response("Not found", { status: 404 });
    }

    try {
      if (pathname === "/api/paintings" && request.method === "GET") {
        return await listPaintings(env);
      }

      const paintingMatch = pathname.match(/^\/api\/paintings\/([^/]+)$/);
      if (paintingMatch && request.method === "GET") {
        return await getPainting(env, paintingMatch[1]);
      }

      if (pathname === "/api/bids" && request.method === "POST") {
        return await placeBid(request, env);
      }

      const imageMatch = pathname.match(/^\/api\/images\/([^/]+)$/);
      if (imageMatch && request.method === "GET") {
        return await serveImage(env, imageMatch[1]);
      }

      if (pathname === "/api/admin/login" && request.method === "POST") {
        return await adminLogin(request, env);
      }

      if (pathname === "/api/admin/paintings" && request.method === "POST") {
        return await withAuth(request, env, (req) => createPainting(req, env));
      }

      const adminPaintingMatch = pathname.match(/^\/api\/admin\/paintings\/([^/]+)$/);
      if (adminPaintingMatch && request.method === "PUT") {
        return await withAuth(request, env, (req) => updatePainting(req, env, adminPaintingMatch[1]));
      }
      if (adminPaintingMatch && request.method === "DELETE") {
        return await withAuth(request, env, () => deletePainting(env, adminPaintingMatch[1]));
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      return json({ error: err.message || "Server error" }, 500);
    }
  },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function slugify(text) {
  return (
    text
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/(^-|-$)/g, "") || "painting"
  );
}

async function withAuth(request, env, handler) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) return json({ error: "Not logged in" }, 401);
  const session = await env.ART_DATA.get(`session:${token}`);
  if (!session) return json({ error: "Session expired, log in again" }, 401);
  return handler(request);
}

async function adminLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  if (!body.password || body.password !== env.ADMIN_PASSWORD) {
    return json({ error: "Wrong password" }, 401);
  }
  const token = crypto.randomUUID();
  await env.ART_DATA.put(`session:${token}`, "1", { expirationTtl: SESSION_TTL_SECONDS });
  return json({ token });
}

async function getIndex(env) {
  const raw = await env.ART_DATA.get("paintings:index");
  return raw ? JSON.parse(raw) : [];
}

async function saveIndex(env, ids) {
  await env.ART_DATA.put("paintings:index", JSON.stringify(ids));
}

async function listPaintings(env) {
  const ids = await getIndex(env);
  const paintings = [];
  for (const id of ids) {
    const raw = await env.ART_DATA.get(`painting:${id}`);
    if (raw) paintings.push(JSON.parse(raw));
  }
  return json({ paintings });
}

async function getPainting(env, id) {
  const raw = await env.ART_DATA.get(`painting:${id}`);
  if (!raw) return json({ error: "Not found" }, 404);
  const painting = JSON.parse(raw);
  const bidsRaw = await env.ART_DATA.get(`bids:${id}`);
  const bids = bidsRaw ? JSON.parse(bidsRaw) : [];
  const publicBids = bids
    .slice()
    .sort((a, b) => b.createdAt - a.createdAt)
    .map((b) => ({ name: b.name, amount: b.amount, createdAt: b.createdAt }));
  return json({ painting, bids: publicBids });
}

async function storeImages(env, id, formData) {
  const files = formData.getAll("images").filter((f) => f && typeof f.arrayBuffer === "function" && f.size > 0);
  const imageIds = [];
  let i = 0;
  for (const file of files) {
    const imageId = `${id}-${Date.now().toString(36)}-${i++}`;
    const bytes = await file.arrayBuffer();
    await env.ART_DATA.put(`image:${imageId}`, bytes, {
      metadata: { contentType: file.type || "image/jpeg" },
    });
    imageIds.push(imageId);
  }
  return imageIds;
}

async function createPainting(request, env) {
  const formData = await request.formData();
  const title = (formData.get("title") || "").toString().trim();
  const description = (formData.get("description") || "").toString().trim();
  const startingBid = Number(formData.get("startingBid") || 0);

  if (!title) return json({ error: "Title is required" }, 400);
  if (!Number.isFinite(startingBid) || startingBid < 0) {
    return json({ error: "Starting price must be a positive number" }, 400);
  }

  const ids = await getIndex(env);
  let id = slugify(title);
  if (ids.includes(id)) id = `${id}-${Date.now().toString(36)}`;

  const images = await storeImages(env, id, formData);

  const painting = {
    id,
    title,
    description,
    startingBid,
    currentBid: startingBid,
    highestBidderName: null,
    bidCount: 0,
    images,
    status: "available",
    createdAt: Date.now(),
  };

  await env.ART_DATA.put(`painting:${id}`, JSON.stringify(painting));
  ids.unshift(id);
  await saveIndex(env, ids);

  return json({ painting }, 201);
}

async function updatePainting(request, env, id) {
  const raw = await env.ART_DATA.get(`painting:${id}`);
  if (!raw) return json({ error: "Not found" }, 404);
  const painting = JSON.parse(raw);

  const formData = await request.formData();
  const title = formData.get("title");
  const description = formData.get("description");
  const status = formData.get("status");
  const removeImages = formData.getAll("removeImage").map(String);

  if (title !== null && title.toString().trim()) painting.title = title.toString().trim();
  if (description !== null) painting.description = description.toString().trim();
  if (status !== null && ["available", "sold", "archived"].includes(status.toString())) {
    painting.status = status.toString();
  }

  for (const imageId of removeImages) {
    await env.ART_DATA.delete(`image:${imageId}`);
    painting.images = painting.images.filter((i) => i !== imageId);
  }

  const newImages = await storeImages(env, id, formData);
  painting.images = [...painting.images, ...newImages];

  await env.ART_DATA.put(`painting:${id}`, JSON.stringify(painting));
  return json({ painting });
}

async function deletePainting(env, id) {
  const raw = await env.ART_DATA.get(`painting:${id}`);
  if (!raw) return json({ error: "Not found" }, 404);
  const painting = JSON.parse(raw);

  for (const imageId of painting.images || []) {
    await env.ART_DATA.delete(`image:${imageId}`);
  }
  await env.ART_DATA.delete(`painting:${id}`);
  await env.ART_DATA.delete(`bids:${id}`);

  const ids = (await getIndex(env)).filter((i) => i !== id);
  await saveIndex(env, ids);

  return json({ ok: true });
}

async function placeBid(request, env) {
  const body = await request.json().catch(() => ({}));
  const paintingId = (body.paintingId || "").toString();
  const name = (body.name || "").toString().trim();
  const amount = Number(body.amount);

  if (!paintingId || !name) return json({ error: "Name and painting are required" }, 400);
  if (!Number.isFinite(amount) || amount <= 0) return json({ error: "Enter a valid bid amount" }, 400);

  const raw = await env.ART_DATA.get(`painting:${paintingId}`);
  if (!raw) return json({ error: "Painting not found" }, 404);
  const painting = JSON.parse(raw);

  if (painting.status !== "available") return json({ error: "This piece is no longer available" }, 400);
  if (amount <= painting.currentBid) {
    return json({ error: `Bid must be higher than the current bid of $${painting.currentBid}` }, 400);
  }

  const bidsRaw = await env.ART_DATA.get(`bids:${paintingId}`);
  const bids = bidsRaw ? JSON.parse(bidsRaw) : [];
  bids.push({
    name,
    email: (body.email || "").toString().trim(),
    amount,
    createdAt: Date.now(),
  });
  await env.ART_DATA.put(`bids:${paintingId}`, JSON.stringify(bids));

  painting.currentBid = amount;
  painting.highestBidderName = name;
  painting.bidCount = (painting.bidCount || 0) + 1;
  await env.ART_DATA.put(`painting:${paintingId}`, JSON.stringify(painting));

  return json({ painting });
}

async function serveImage(env, imageId) {
  const { value, metadata } = await env.ART_DATA.getWithMetadata(`image:${imageId}`, "arrayBuffer");
  if (!value) return new Response("Not found", { status: 404 });
  return new Response(value, {
    headers: {
      "content-type": (metadata && metadata.contentType) || "image/jpeg",
      "cache-control": "public, max-age=31536000, immutable",
    },
  });
}
