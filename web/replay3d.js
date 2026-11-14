/* 3D replay. Three axes carry three questions at once:
   across  = which device, up = what kind of activity, depth = when.
   Quiet gaps are compressed so the camera flies from one burst of activity to the next. */
import * as THREE from "/static/vendor/three.module.min.js";

let R = null;
const GAP_CAP = 25 * 60000;      // idle time longer than this is folded
const Z_PER_MIN = 1.1, TRACK = 15, LIFT = 2.6;

function label(text, opts = {}) {
  const c = document.createElement("canvas"), g = c.getContext("2d");
  const font = `${opts.weight || 600} 44px "Avenir Next", "Segoe UI", sans-serif`;
  g.font = font;
  c.width = Math.ceil(g.measureText(text).width) + 24; c.height = 64;
  g.font = font; g.fillStyle = opts.color || "#16233a"; g.textBaseline = "middle";
  g.fillText(text, 12, 34);
  const tex = new THREE.CanvasTexture(c);
  tex.anisotropy = 4;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
  const k = opts.size || 0.05;
  s.scale.set(c.width * k, c.height * k, 1);
  return s;
}

export function hide() {
  if (!R) return;
  cancelAnimationFrame(R.raf);
  R.ro.disconnect();
  R.renderer.dispose();
  R.canvas.replaceWith(R.canvas.cloneNode(false));   // drop listeners with the old node
  R = null;
}

export function show(canvas, S, api) {
  hide();
  const ev = api.visible();
  const devices = [...new Map(ev.map((f) => [f._dev, 0])).keys()];
  const lanes = api.LANES.filter((l) => ev.some((f) => f.lane === l));
  // compressed clock: z grows with time, but long silences add only a short hop
  const times = [...new Set(ev.map((f) => +f._t))].sort((a, b) => a - b);
  const zOf = new Map();
  let z = 0;
  times.forEach((t, i) => { if (i) z += Math.min(t - times[i - 1], GAP_CAP) / 60000 * Z_PER_MIN + (t - times[i - 1] > GAP_CAP ? 10 : 0); zOf.set(t, z); });
  const zEnd = z;
  const pos = (f) => new THREE.Vector3((devices.indexOf(f._dev) - (devices.length - 1) / 2) * TRACK, 1.2 + lanes.indexOf(f.lane) * LIFT, -zOf.get(+f._t));

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
  renderer.setPixelRatio(Math.min(2, window.devicePixelRatio));
  const scene = new THREE.Scene();
  scene.background = new THREE.Color("#fcfcfb");
  scene.fog = new THREE.Fog("#fcfcfb", 120, 330);
  const camera = new THREE.PerspectiveCamera(46, 2, 0.1, 600);
  scene.add(new THREE.HemisphereLight("#ffffff", "#c8ced8", 1.15));
  const sun = new THREE.DirectionalLight("#ffffff", 0.9);
  sun.position.set(20, 40, 20);
  scene.add(sun);

  // device tracks on the floor, with a name at the near end and repeated along the way
  const half = (devices.length * TRACK) / 2;
  const trackLabels = [];
  devices.forEach((d, i) => {
    const x = (i - (devices.length - 1) / 2) * TRACK;
    const strip = new THREE.Mesh(new THREE.PlaneGeometry(TRACK - 2, zEnd + 40), new THREE.MeshBasicMaterial({ color: i % 2 ? "#eef0f3" : "#e6e9ed" }));
    strip.rotation.x = -Math.PI / 2; strip.position.set(x, 0, -zEnd / 2);
    scene.add(strip);
    const s = label(d, { size: 0.032 }); s.userData.x = x; trackLabels.push(s); scene.add(s);
  });
  // a gate wherever the day changes or a long silence was folded
  let lastDay = "";
  const dayFmt = new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", weekday: "short", day: "2-digit", month: "short" });
  const clock = new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit" });
  times.forEach((t, i) => {
    const day = dayFmt.format(t), folded = i && t - times[i - 1] > GAP_CAP;
    if (day === lastDay && !folded) return;
    const zz = -zOf.get(t) + 5;
    const bar = new THREE.Mesh(new THREE.BoxGeometry(half * 2 + 6, 0.08, 0.25), new THREE.MeshBasicMaterial({ color: day !== lastDay ? "#16233a" : "#98a1ae" }));
    bar.position.set(0, 0.05, zz); scene.add(bar);
    const s = label(day !== lastDay ? `${day}, ${clock.format(t)}` : clock.format(t), { size: day !== lastDay ? 0.07 : 0.05, color: day !== lastDay ? "#16233a" : "#47536a" });
    s.position.set(-half - 9, 1.4, zz); scene.add(s);
    lastDay = day;
  });
  lanes.forEach((l, i) => { const s = label(api.LANE_NAME[l], { size: 0.04, color: api.laneColor(l) }); s.position.set(half + 7, 1.2 + i * LIFT, 6); scene.add(s); });

  // one sphere per finding, on a thin post so its device and time stay readable
  const geo = new THREE.SphereGeometry(1, 20, 14);
  const meshes = [];
  const group = new THREE.Group();
  const stack = new Map();
  for (const f of ev) {
    const p = pos(f), key = `${p.x}|${p.y}|${p.z.toFixed(1)}`, n = stack.get(key) || 0;
    stack.set(key, n + 1);
    p.x += ((n % 5) - 2) * 1.5 * (n ? 1 : 0); p.z -= Math.floor(n / 5) * 1.5;
    const m = new THREE.Mesh(geo, new THREE.MeshLambertMaterial({ color: api.laneColor(f.lane) }));
    m.scale.setScalar([0, 0.42, 0.62, 0.85][f.severity]);
    m.position.copy(p); m.userData.f = f;
    group.add(m); meshes.push(m);
    const post = new THREE.Mesh(new THREE.CylinderGeometry(0.04, 0.04, p.y, 6), new THREE.MeshBasicMaterial({ color: "#c3c9d2" }));
    post.position.set(p.x, p.y / 2, p.z); group.add(post);
  }
  scene.add(group);
  const thread = new THREE.Group();
  scene.add(thread);
  const head = new THREE.Mesh(new THREE.BoxGeometry(half * 2 + 4, 0.06, 0.35), new THREE.MeshBasicMaterial({ color: "#16233a" }));
  scene.add(head);

  const state = { z: 0, target: 0, yaw: -0.38, pitch: 0.52, dist: 78, beat: -2, journey: undefined, sel: undefined };
  const byFinding = new Map(meshes.map((m) => [m.userData.f.id, m]));

  function sync() {
    const b = S.tl.keyBeats[S.beat];
    if (S.beat !== state.beat) {
      state.beat = S.beat;
      if (b) { const m = b.findings.map((id) => byFinding.get(id)).find(Boolean); if (m) state.target = -m.position.z; }
    }
    const sel = S.sel?.finding || (S.sel?.group || []).join();
    if (S.journey !== state.journey || sel !== state.sel) {
      state.journey = S.journey; state.sel = sel;
      const jset = S.journey ? new Set(S.journey.sightings.map((s) => s.finding)) : null;
      const picked = new Set(S.sel?.finding ? [S.sel.finding] : S.sel?.group || []);
      for (const m of meshes) {
        const on = !jset || jset.has(m.userData.f.id);
        m.material.transparent = !on; m.material.opacity = on ? 1 : 0.12;
        m.material.emissive.set(picked.has(m.userData.f.id) ? "#16233a" : "#000000");
      }
      thread.clear();
      if (jset) {
        const pts = meshes.filter((m) => jset.has(m.userData.f.id)).sort((a, c) => a.userData.f._t - c.userData.f._t).map((m) => m.position.clone());
        if (pts.length > 1) {
          const arc = [];
          pts.forEach((p, i) => { if (i) { const q = pts[i - 1], mid = q.clone().lerp(p, 0.5); mid.y += 6 + q.distanceTo(p) * 0.08; arc.push(mid); } arc.push(p); });
          thread.add(new THREE.Mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(arc), 120, 0.16, 8), new THREE.MeshBasicMaterial({ color: "#16233a" })));
          state.target = -pts[0].z + (pts[0].z - pts.at(-1).z) / 2;
          state.dist = Math.max(78, (pts[0].z - pts.at(-1).z) * 0.8);
        }
      }
    }
  }

  function frame() {
    R.raf = requestAnimationFrame(frame);
    sync();
    state.z += (state.target - state.z) * 0.07;
    const focus = new THREE.Vector3(0, 4, -state.z);
    camera.position.set(focus.x + Math.sin(state.yaw) * Math.cos(state.pitch) * state.dist, focus.y + Math.sin(state.pitch) * state.dist,
      focus.z + Math.cos(state.yaw) * Math.cos(state.pitch) * state.dist);
    camera.lookAt(focus);
    head.position.set(0, 0.06, -state.z);
    for (const s of trackLabels) s.position.set(s.userData.x, 0.5, -state.z + 9);   // names ride with the playhead
    renderer.render(scene, camera);
  }
  function size() {
    const w = canvas.clientWidth, hgt = canvas.clientHeight;
    renderer.setSize(w, hgt, false); camera.aspect = w / hgt; camera.updateProjectionMatrix();
  }
  const ro = new ResizeObserver(size);
  ro.observe(canvas);

  let drag = null;
  canvas.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY, moved: false }; canvas.setPointerCapture(e.pointerId); });
  canvas.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    state.yaw -= dx * 0.005; state.pitch = Math.min(1.35, Math.max(0.12, state.pitch + dy * 0.004));
    drag.x = e.clientX; drag.y = e.clientY;
  });
  canvas.addEventListener("pointerup", (e) => {
    const wasDrag = drag?.moved; drag = null;
    if (wasDrag) return;
    const box = canvas.getBoundingClientRect(), ray = new THREE.Raycaster();
    ray.setFromCamera(new THREE.Vector2(((e.clientX - box.left) / box.width) * 2 - 1, -((e.clientY - box.top) / box.height) * 2 + 1), camera);
    const hit = ray.intersectObjects(meshes)[0];
    if (hit) api.select({ finding: hit.object.userData.f.id });
  });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    if (e.ctrlKey || e.shiftKey) state.dist = Math.min(220, Math.max(18, state.dist * (1 + e.deltaY * 0.001)));
    else state.target = Math.min(zEnd + 10, Math.max(-10, state.target + e.deltaY * 0.08));
  }, { passive: false });

  R = { renderer, canvas, raf: 0, ro };
  size();
  frame();
}
