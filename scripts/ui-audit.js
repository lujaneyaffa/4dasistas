// UI audit — paste/eval in the browser console (or run through the browser tool) on a phone-width viewport.
// Reports: (1) text clipped by its box, (2) page wider than the screen, (3) visible text blocks that overlap each other.
(function(){
  const out = { clipped:[], wide:null, overlap:[] };
  const vw = window.innerWidth;
  if(document.documentElement.scrollWidth > vw + 1) out.wide = { scrollWidth: document.documentElement.scrollWidth, viewport: vw };
  const visible = el => { const r = el.getBoundingClientRect(), cs = getComputedStyle(el); return r.width > 2 && r.height > 2 && cs.visibility !== 'hidden' && cs.display !== 'none' && Number(cs.opacity) > 0.05; };
  const label = el => (el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '')) + ' "' + (el.innerText || '').trim().replace(/\s+/g, ' ').slice(0, 40) + '"';
  const inFixed = el => { for(let n = el; n && n !== document.body; n = n.parentElement){ const p = getComputedStyle(n).position; if(p === 'fixed' || p === 'sticky') return true; } return false; };
  const skip = el => !!el.closest('.leaflet-container, .mem-pop, .idea-pop-card, #pushGate, .mem-pop-card') || inFixed(el); // map pins, pop-ups and the fixed bottom bar legitimately sit on top of the page
  const all = [...document.body.querySelectorAll('*')].filter(el => !['SCRIPT','STYLE','svg','path','IMG','INPUT','SELECT','TEXTAREA','OPTION'].includes(el.tagName) && visible(el) && !skip(el));
  // 1) clipped text: a box that hides overflow while its text is wider/taller than the box
  for(const el of all){
    const cs = getComputedStyle(el);
    const hasText = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if(!hasText) continue;
    const clipX = /(hidden|clip)/.test(cs.overflowX) && el.scrollWidth > el.clientWidth + 2 && cs.textOverflow !== 'ellipsis';
    const clipY = /(hidden|clip)/.test(cs.overflowY) && el.scrollHeight > el.clientHeight + 2 && cs.webkitLineClamp === 'none';
    if(clipX || clipY) out.clipped.push(label(el));
  }
  // 2) overlapping text: compare the rectangles of the text itself (not the boxes)
  const texts = [];
  for(const el of all){
    const own = [...el.childNodes].filter(n => n.nodeType === 3 && n.textContent.trim());
    if(!own.length) continue;
    const rng = document.createRange(); let rect = null;
    for(const n of own){ rng.selectNodeContents(n); for(const r of rng.getClientRects()){ if(r.width < 3 || r.height < 3) continue; rect = rect ? { left:Math.min(rect.left, r.left), top:Math.min(rect.top, r.top), right:Math.max(rect.right, r.right), bottom:Math.max(rect.bottom, r.bottom) } : { left:r.left, top:r.top, right:r.right, bottom:r.bottom }; } }
    if(rect){ // clip to scroll / overflow-hidden ancestors: text scrolled out of view isn't overlapping anything
      for(let n = el.parentElement; n && n !== document.body && rect; n = n.parentElement){ const cs = getComputedStyle(n); if(/(hidden|auto|scroll|clip)/.test(cs.overflowX + cs.overflowY)){ const b = n.getBoundingClientRect(); rect = { left:Math.max(rect.left, b.left), top:Math.max(rect.top, b.top), right:Math.min(rect.right, b.right), bottom:Math.min(rect.bottom, b.bottom) }; if(rect.right - rect.left < 3 || rect.bottom - rect.top < 3) rect = null; } }
    }
    if(rect && rect.bottom > 0 && rect.top < window.innerHeight * 6) texts.push({ el, rect, z: 0 });
  }
  for(let i = 0; i < texts.length && i < 700; i++) for(let j = i + 1; j < texts.length && j < 700; j++){
    const a = texts[i], b = texts[j];
    if(a.el.contains(b.el) || b.el.contains(a.el)) continue;
    const ix = Math.min(a.rect.right, b.rect.right) - Math.max(a.rect.left, b.rect.left), iy = Math.min(a.rect.bottom, b.rect.bottom) - Math.max(a.rect.top, b.rect.top);
    if(ix > 3 && iy > 3){
      const areaA = (a.rect.right - a.rect.left) * (a.rect.bottom - a.rect.top), areaB = (b.rect.right - b.rect.left) * (b.rect.bottom - b.rect.top), inter = ix * iy;
      if(inter / Math.min(areaA, areaB) > 0.25){
        // ignore if one is above the other in a different stacking context (e.g. a popup over the page)
        const pa = document.elementFromPoint((Math.max(a.rect.left, b.rect.left) + Math.min(a.rect.right, b.rect.right)) / 2, (Math.max(a.rect.top, b.rect.top) + Math.min(a.rect.bottom, b.rect.bottom)) / 2);
        if(pa && !a.el.contains(pa) && !b.el.contains(pa) && !pa.contains(a.el) && !pa.contains(b.el)) continue;
        out.overlap.push(label(a.el) + '  ⟷  ' + label(b.el));
      }
    }
  }
  out.clipped = [...new Set(out.clipped)].slice(0, 25); out.overlap = [...new Set(out.overlap)].slice(0, 25);
  return out;
})();
