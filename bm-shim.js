/* A stand-in for the Supabase client so the ORIGINAL ladies-badminton app runs unchanged on 4DS (data + logins now live in 4DS).
   Implements only what that app uses: from().select/insert/update/upsert/delete + filters, rpc(), auth (owner/coach), storage.upload. */
(function(){
  var API = location.origin;
  function ls(k, v){ try { if(v === undefined) return localStorage.getItem(k); if(v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch(e){} return null; }
  function memberToken(){ try { var s = JSON.parse(ls('cmSession') || 'null'); return (s && s.token) || ''; } catch(e){ return ''; } } // ONE sign-in: the 4DS session is the only session
  function headers(){ var h = { 'Content-Type':'application/json' }, t = memberToken(), c = ls('bm_coach'), k = ls('kiosk_key_v1'); if(t) h['Authorization'] = 'Bearer ' + t; if(c) h['X-BM-Coach'] = c; if(k) h['X-Kiosk-Key'] = k; return h; }
  async function post(path, body){
    var r, d;
    try { r = await fetch(API + path, { method:'POST', credentials:'include', headers:headers(), body:JSON.stringify(body || {}) }); d = await r.json().catch(function(){ return {}; }); }
    catch(e){ return { data:null, error:{ message:'Failed to fetch' } }; }
    if(typeof d.error === 'string') return { data:null, error:{ message:d.error } };
    if(!r.ok && !d.error) return { data:null, error:{ message:'Request failed (' + r.status + ')' } };
    return d;
  }
  function Q(t){ this.t = t; this.op = 'select'; this.f = []; this.o = []; this.payload = null; this.oc = ''; this.lim = 0; this.sg = false; this.mb = false; this.ret = false; }
  Q.prototype.select = function(){ if(this.op !== 'select') this.ret = true; return this; };
  Q.prototype.insert = function(p){ this.op = 'insert'; this.payload = p; return this; };
  Q.prototype.upsert = function(p, o){ this.op = 'upsert'; this.payload = p; this.oc = (o && o.onConflict) || ''; return this; };
  Q.prototype.update = function(p){ this.op = 'update'; this.payload = p; return this; };
  Q.prototype.delete = function(){ this.op = 'delete'; return this; };
  ['eq','neq','gt','gte','lt','lte'].forEach(function(n){ Q.prototype[n] = function(c, v){ this.f.push({ op:n, col:c, val:v }); return this; }; });
  Q.prototype.in = function(c, v){ this.f.push({ op:'in', col:c, val:v }); return this; };
  Q.prototype.order = function(c, o){ this.o.push({ col:c, asc:!(o && o.ascending === false) }); return this; };
  Q.prototype.limit = function(n){ this.lim = n; return this; };
  Q.prototype.single = function(){ this.sg = true; return this; };
  Q.prototype.maybeSingle = function(){ this.mb = true; return this; };
  Q.prototype.then = function(res, rej){
    var self = this;
    return post('/api/bm/q', { table:self.t, op:self.op, filters:self.f, order:self.o, payload:self.payload, onConflict:self.oc, limit:self.lim, single:self.sg, maybe:self.mb, returning:self.ret }).then(res, rej);
  };
  async function rpc(name, args){
    args = args || {};
    if(name === 'login_player'){ // sign in through the normal 4DS login (phone number or username + PIN), then fetch the player row
      var lr, ld;
      try { lr = await fetch(API + '/api/login', { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify({ username:args.p_username, pin:args.p_pin }) }); ld = await lr.json().catch(function(){ return {}; }); }
      catch(e){ return { data:null, error:{ message:'Failed to fetch' } }; }
      if(!lr.ok) return { data:null, error:{ message:ld.error || 'Phone number or PIN is incorrect' } };
      ls('cmSession', JSON.stringify(ld)); // (the same sign-in works on the rest of 4DS)
    }
    var r = await post('/api/bm/rpc', { name:name, args:args });
    if(name === 'signup_player' && r.data && r.data.token){ // sign them in to 4DS too (same account everywhere)
      try { var lr2 = await fetch(API + '/api/login', { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify({ username:args.p_phone, pin:args.p_pin }) }); var ld2 = await lr2.json().catch(function(){ return {}; }); if(lr2.ok) ls('cmSession', JSON.stringify(ld2)); } catch(e){}
    }
    return r;
  }
  var auth = {
    getSession: async function(){ var r = await post('/api/bm/session'); return { data:{ session:(r && r.session) || null }, error:null }; },
    signInWithPassword: async function(c){ var r = await post('/api/bm/auth', { email:c.email, password:c.password }); if(r.error) return { data:{ session:null }, error:{ message:r.error.message || String(r.error) } }; if(r.session && r.session.user.id === 'coach') ls('bm_coach', r.session.access_token); return { data:{ session:r.session }, error:null }; },
    signOut: async function(){ await post('/api/bm/logout'); ls('bm_coach', null); try { await fetch(API + '/api/admin/logout', { method:'POST', credentials:'include' }); } catch(e){} return { error:null }; }, // (the owner IS the 4DS main admin, so this signs out of both)
    onAuthStateChange: function(){ return { data:{ subscription:{ unsubscribe:function(){} } } }; }
  };
  var storage = { from: function(bucket){ return {
    upload: async function(path, file){
      var r, d; try { var h = headers(); h['Content-Type'] = (file && file.type) || 'image/jpeg'; r = await fetch(API + '/api/bm/upload?path=' + encodeURIComponent(path), { method:'POST', credentials:'include', headers:h, body:file }); d = await r.json().catch(function(){ return {}; }); } catch(e){ return { data:null, error:{ message:'Failed to fetch' } }; }
      if(!r.ok) return { data:null, error:{ message:(d.error && d.error.message) || (typeof d.error === 'string' ? d.error : 'Upload failed') } };
      return { data:{ path:path }, error:null };
    },
    getPublicUrl: function(p){ return { data:{ publicUrl:API + '/storage/v1/object/public/' + bucket + '/' + p } }; }
  }; } };
  // One sign-in across 4DS and badminton: if this person is already logged in to 4DS, recognise them straight away (the app reads this at start-up, so it has to be synchronous).
  try {
    var mine = ls('mb_auth'), tok = memberToken();
    if(mine && !tok) ls('mb_auth', null); // an old badminton-only login: ask them to log in again with their 4DS PIN
    else if(!mine && tok){
      var x = new XMLHttpRequest(); x.open('POST', API + '/api/bm/rpc', false); x.setRequestHeader('Content-Type', 'application/json'); x.setRequestHeader('Authorization', 'Bearer ' + tok);
      x.send(JSON.stringify({ name:'whoami', args:{} }));
      var d = x.status === 200 ? JSON.parse(x.responseText) : null;
      if(d && d.data && d.data[0] && d.data[0].username) ls('mb_auth', JSON.stringify({ username:d.data[0].username, pin:'' }));
    }
  } catch(e){}
  window.supabase = { createClient: function(){ return { from:function(t){ return new Q(t); }, rpc:rpc, auth:auth, storage:storage }; } };
})();
