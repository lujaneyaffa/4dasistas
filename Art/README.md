# Lujane Art

A small, separate Cloudflare Worker for selling paintings with eBay-style
bidding. Lives in this folder but deploys independently from 4dasistas.ca
— it does not share a domain, deploy pipeline, or KV namespace with it
beyond both being Cloudflare Workers on the same account.

- Public gallery: `public/index.html` — browse paintings, click one to
  see the full description, bid history, and place a bid.
- Admin: `public/admin.html` — password-gated (see below), add/edit/
  delete paintings, upload photos, change status, mark sold.
- API: `src/worker.js` — everything under `/api/*`.
- Storage: Cloudflare KV only (binding `ART_DATA`, already created —
  id is in `wrangler.toml`). Painting data, bids, and the photos
  themselves (as raw bytes) all live there. No R2, no Supabase, no
  external accounts needed. (R2 wasn't enabled on the Cloudflare
  account when this was built — if you'd rather serve images from R2
  later, `storeImages`/`serveImage` in `worker.js` are the only two
  functions that would need to change.)

## First-time deploy

From inside this `Art/` folder:

```
npx wrangler login
npx wrangler secret put ADMIN_PASSWORD
```

When prompted, type `122139` and press enter. This keeps the password
out of the repo (it's stored encrypted on Cloudflare, not in
`wrangler.toml`).

```
npx wrangler deploy
```

Wrangler will print the live URL, something like
`https://lujane-art.<your-subdomain>.workers.dev` — that's the link to
share. It also shows up in the Cloudflare dashboard under
Workers & Pages → `lujane-art`.

## Redeploying after changes

```
npx wrangler deploy
```

That's it — no build step, no separate frontend deploy.

## Changing the admin password later

```
npx wrangler secret put ADMIN_PASSWORD
```

and enter the new password. Existing admin logins (sessions) stay valid
for up to 7 days after that — log out and back in on `admin.html` to
pick up the change immediately.

## How bidding works

Each painting has a starting price and a current bid (they're the same
until the first bid comes in). Anyone can view the gallery and place a
bid with their name, email, and amount — a bid must beat the current
bid to be accepted. There's no auto-checkout or payment built in: you
see who's bidding and for how much in the admin panel and on the
painting's own bid history, and you follow up with the winner yourself
(by the email they gave) however you normally handle a sale — e-transfer,
in person, etc. If you want real payments wired in later, that's a
separate, bigger piece of work (Stripe or similar) — flag it if you want
it and it can be added on top of this.
