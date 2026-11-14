/* Case Replay front end. Plain ES modules + d3, no build step. */
const d3 = window.d3;
const $ = (s) => document.querySelector(s);
const LANES = ["communication", "web", "devices", "files", "cloud", "coverup", "system"];
const LANE_NAME = { communication: "Messages", web: "Web", devices: "Devices", files: "Files", cloud: "Cloud",
  coverup: "Cover-up", system: "Programs" };
const KIND_NAME = { deleted_file_recovered: "Deleted file recovered", carved_file: "File carved from raw data",
  disguised_file: "File under a false name", volume_formatted: "Volume formatted", wiping_tool: "Wiping tool",
  file_wiped: "File securely wiped", file_renamed: "File renamed", file_listed: "File on the device",
  file_opened: "File opened", file_deleted: "File removed", recycle_bin: "Recycle Bin", web_search: "Web search",
  web_visit: "Web visit", web_download: "Download", usb_connected: "Device connected",
  program_installed: "Program installed", program_executed: "Program run", program_uninstalled: "Program removed",
  cloud_activity: "Cloud storage", evidence_link: "Same content, different place", system_info: "Evidence intake",
  note: "Inference awaiting review", email: "Email", cd_burned: "Disc burned" };
const R = [0, 4.5, 6.5, 8.5];
const css = getComputedStyle(document.documentElement);
const laneColor = (l) => css.getPropertyValue(`--lane-${l}`).trim() || "#98a1ae";
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const S = { meta: null, cases: [], caseId: null, tl: null, mode: "lane", sev: 1, q: "", hidden: new Set(),
  showRef: false, sel: null, journey: null, beat: -1, playing: false, timer: null, logNext: 0, running: null,
  tab: "files", tasks: [], lastReload: 0, view3d: false, skip: new Set() };
let wall = (iso) => new Date(iso);
let chart = null;

const h = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = async (path, opts) => {
  const r = await fetch(path, opts && { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(opts) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.headers.get("content-type")?.includes("json") ? r.json() : r.text();
};

function makeWall(tz) {
  const fmt = new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit",
    day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const cache = new Map();
  return (iso) => {
    let d = cache.get(iso);
    if (!d) {
      const p = {};
      for (const x of fmt.formatToParts(new Date(iso))) p[x.type] = x.value;
      d = new Date(Date.UTC(+p.year, p.month - 1, +p.day, +p.hour, +p.minute, +p.second));
      cache.set(iso, d);
    }
    return d;
  };
}
const fDay = d3.utcFormat("%a %d %b %Y"), fClock = d3.utcFormat("%H:%M:%S"), fShort = d3.utcFormat("%a %d %b, %H:%M:%S");
const when = (iso) => (iso ? fShort(wall(iso)) : "no time recorded");
const byId = (id) => S.tl?.index.get(id);

/* ---------- loading ---------- */
async function boot() {
  S.meta = await api("/api/meta");
  S.cases = await api("/api/cases");
  const sel = $("#caseSelect");
  sel.innerHTML = S.cases.map((c) => `<option value="${h(c.id)}">${h(c.name)}</option>`).join("") || "<option>No cases yet</option>";
  const wanted = new URLSearchParams(location.search).get("case");
  S.caseId = S.cases.find((c) => c.id === wanted)?.id || S.cases.find((c) => c.finding_count)?.id || S.cases[0]?.id || null;
  if (S.caseId) sel.value = S.caseId;
  bind();
  if (S.caseId) await openCase(S.caseId);
  else renderEmpty();
  setInterval(poll, 1200);
}

async function openCase(id) {
  stopPlay();
  Object.assign(S, { caseId: id, sel: null, journey: null, beat: -1, logNext: 0, hidden: new Set(), q: "", skip: new Set() });
  $("#search").value = "";
  $("#log").innerHTML = "";
  history.replaceState(null, "", `?case=${encodeURIComponent(id)}`);
  await loadTimeline(true);
  await poll();
}

async function loadTimeline(fit) {
  const tl = await api(`/api/cases/${S.caseId}/timeline`);
  wall = makeWall(tl.timezone);
  tl.index = new Map([...tl.events, ...tl.undated].map((f) => [f.id, f]));
  tl.journeyOf = new Map();
  for (const j of tl.journeys) for (const s of j.sightings) tl.journeyOf.set(s.finding, j);
  tl.keyBeats = tl.beats.filter((b) => b.severity >= 2);
  for (const f of tl.events) {
    f._t = wall(f.time);
    f._dev = f.entities.find((e) => e.type === "device")?.label || "Unattributed";
    f._hay = (f.title + " " + f.summary + " " + (f.data.name || "") + " " + f.entities.map((e) => e.label).join(" ")).toLowerCase();
  }
  S.tl = tl;
  S.lastReload = Date.now();
  renderBar(); renderRail(); renderLegend(); renderDays();
  $("#refToggleWrap").hidden = !tl.reference;
  $("#scoreTab").hidden = !tl.score;
  if (!tl.score && S.tab === "score") S.tab = "files";
  buildChart(fit);
  renderCaption(); renderTab(); renderExhibit(); refresh3d();
}

/* ---------- top bar and rail ---------- */
function renderBar() {
  const c = S.tl.case, st = S.tl.stats;
  $("#caseMeta").innerHTML = `${c.synthetic ? '<span class="tag">synthetic practice data</span> ' : ""}` +
    `<b>${st.findings}</b> findings &nbsp; <b>${st.recovered}</b> files recovered &nbsp; <b>${st.disguised}</b> false names &nbsp; ` +
    `<b>${st.coverup}</b> cover-up traces &nbsp; times shown in ${h(c.timezone)}`;
  $("#reportLink").href = `/api/cases/${S.caseId}/report?format=html`;
}

function renderRail() {
  const c = S.tl.case;
  const counts = d3.rollup([...S.tl.events, ...S.tl.undated], (v) => v.length, (f) => f.data.image_id);
  $("#evidence").innerHTML = c.images.map((im) => {
    const file = im.path.split(/[\\/]/).pop();
    const hash = im.sha1_expected ? (im.sha1_actual ? (im.sha1_actual.toUpperCase() === im.sha1_expected.toUpperCase() ? "hash verified" : "HASH MISMATCH") : "hash not checked yet") : "";
    const state = im.present ? `${counts.get(im.id) || 0} findings` : '<span class="missing">not on disk</span>';
    return `<li><label class="name"><input type="checkbox" data-image="${h(im.id)}" ${S.skip.has(im.id) || !im.present ? "" : "checked"} ${im.present ? "" : "disabled"} aria-label="Include ${h(im.label)} when sending agents"> ${h(im.label)}</label><span class="state">${state}</span>
      <span class="sub" title="${h(im.path)}">${h(file)}${hash ? " · " + hash : ""}</span></li>`;
  }).join("");
  renderAgents();
  $("#leadBox").innerHTML = S.meta.llm
    ? `<b>Lead investigator</b> (${h(S.meta.model)}) plans the work, delegates to the agents above and writes a cited report.
       <textarea id="leadQ" rows="2" placeholder="Ask a question, or leave empty for a full investigation"></textarea>
       <button id="leadGo" class="primary">Brief the lead</button>`
    : `The six agents above run without a language model. To add the lead investigator, which plans, delegates and writes a cited report, set <code>ANTHROPIC_API_KEY</code> and restart.`;
  $("#leadGo")?.addEventListener("click", async () => {
    try { await api(`/api/cases/${S.caseId}/ask`, { question: $("#leadQ").value }); poll(); } catch (e) { alert(e.message); }
  });
}

function renderAgents() {
  const latest = new Map();
  for (const t of S.tasks) {
    const cur = latest.get(t.agent) || { running: 0, failed: 0, done: 0, findings: 0 };
    cur[t.status] = (cur[t.status] || 0) + 1;
    latest.set(t.agent, cur);
  }
  const found = d3.rollup([...(S.tl?.events || []), ...(S.tl?.undated || [])], (v) => v.length, (f) => f.agent);
  $("#agents").innerHTML = S.meta.order.map((a) => {
    const m = S.meta.agents[a], t = latest.get(a);
    const state = t?.running ? "running" : t?.failed ? "failed" : t?.done ? "done" : "";
    const note = t?.running ? "working" : a === "consensus" ? (S.tl ? `${S.tl.stats.beats} beats` : "") : found.get(a) ? `${found.get(a)} findings` : t?.done ? "nothing found" : "not sent yet";
    return `<li title="${h(m.does)}"><i class="dot ${state}"></i>
      <span class="what"><b>${h(m.verb)}</b><span>${h(m.label)} agent · ${note}</span></span>
      <button data-agent="${a}" ${S.running ? "disabled" : ""}>Send</button></li>`;
  }).join("");
  $("#sendAll").disabled = !!S.running || !S.caseId;
  $("#runState").textContent = S.running ? `${S.running} working` : "";
}

async function poll() {
  if (!S.caseId) return;
  let st;
  try { st = await api(`/api/cases/${S.caseId}/status?since=${S.logNext}`); } catch { return; }
  const log = $("#log");
  for (const l of st.log) {
    const li = document.createElement("li");
    li.innerHTML = `<b>${h(l.agent)}</b> ${h(l.message)}`;
    log.prepend(li);
  }
  while (log.children.length > 250) log.lastChild.remove();
  S.logNext = st.next;
  const was = S.running;
  S.running = st.running; S.tasks = st.tasks;
  renderAgents();
  const total = S.tl ? S.tl.stats.findings + S.tl.stats.rejected : 0;
  if ((was && !st.running) || (st.running && Date.now() - S.lastReload > 3500 && st.findings !== total)) await loadTimeline(!S.tl?.events.length);
}

async function send(agents) {
  const images = S.skip.size ? S.tl.case.images.filter((i) => i.present && !S.skip.has(i.id)).map((i) => i.id) : null;
  if (images && !images.length) { alert("Tick at least one evidence item first."); return; }
  try { await api(`/api/cases/${S.caseId}/dispatch`, { agents, images }); S.running = "agents"; renderAgents(); poll(); }
  catch (e) { alert(e.message); }
}

/* ---------- filters ---------- */
const visible = () => S.tl.events.filter((f) => f.severity >= S.sev && !S.hidden.has(f.lane) && (!S.q || f._hay.includes(S.q)));

function renderLegend() {
  const n = d3.rollup(S.tl.events, (v) => v.length, (f) => f.lane);
  $("#legend").innerHTML = LANES.map((l) => `<button data-lane="${l}" class="${S.hidden.has(l) ? "off" : ""}" aria-pressed="${!S.hidden.has(l)}">
      <i style="background:${laneColor(l)}"></i>${LANE_NAME[l]} <span class="muted">${n.get(l) || 0}</span></button>`).join("") +
    `<span class="sizes">importance <i style="width:7px;height:7px"></i> <i style="width:11px;height:11px"></i> <i style="width:15px;height:15px"></i> key</span>`;
}
function renderDays() {
  $("#days").innerHTML = S.tl.acts.map((a) => `<button data-day="${a.day}" title="${h(a.headline)}">${h(a.label.slice(0, 10))}</button>`).join("");
}

/* ---------- timeline ---------- */
function buildChart(fit) {
  const svg = d3.select("#chart");
  const prev = chart?.xz && !fit ? chart.xz.domain() : null;
  svg.selectAll("*").remove();
  const ev = S.tl.events;
  $("#empty").hidden = ev.length > 0;
  if (!ev.length) { renderEmpty(); chart = null; return; }
  const W = $("#chart").clientWidth, H = $("#chart").clientHeight;
  const m = { l: 148, r: 18, t: 46, b: 70 };
  const rows = S.mode === "lane" ? LANES.filter((l) => ev.some((f) => f.lane === l))
    : [...d3.rollup(ev, (v) => d3.min(v, (f) => +f._t), (f) => f._dev)].sort((a, b) => a[1] - b[1]).map((d) => d[0]);
  const refRow = S.showRef && S.tl.reference;
  const rowH = (H - m.t - m.b) / (rows.length + (refRow ? 1 : 0));
  const rowOf = (f) => rows.indexOf(S.mode === "lane" ? f.lane : f._dev);
  const yOf = (f) => {
    const base = m.t + rowOf(f) * rowH + rowH / 2;
    return S.mode === "lane" ? base : base + (LANES.indexOf(f.lane) - 3) * Math.min(7, rowH / 9);
  };
  const t0 = d3.min(ev, (f) => +f._t), t1 = d3.max(ev, (f) => +(f.time_end ? wall(f.time_end) : f._t));
  const pad = Math.max((t1 - t0) * 0.03, 20 * 60000);
  const x0 = d3.scaleUtc().domain([t0 - pad, t1 + pad]).range([m.l, W - m.r]);
  const g = {};
  svg.append("defs").append("clipPath").attr("id", "clip").append("rect").attr("x", m.l).attr("y", 0).attr("width", W - m.l - m.r).attr("height", H - m.b + 6);
  for (const k of ["days", "rows"]) g[k] = svg.append("g");
  const plot = svg.append("g").attr("clip-path", "url(#clip)");
  for (const k of ["daylabels", "beats", "thread", "marks", "ref", "head"]) g[k] = plot.append("g");
  g.axis = svg.append("g").attr("class", "axis").attr("transform", `translate(0,${H - m.b + 6})`);
  g.mini = svg.append("g").attr("class", "mini").attr("transform", `translate(0,${H - 30})`);

  rows.forEach((r, i) => {
    const y = m.t + i * rowH;
    g.rows.append("line").attr("class", "row-line").attr("x1", 8).attr("x2", W - m.r).attr("y1", y).attr("y2", y);
    g.rows.append("text").attr("class", "row-label").attr("x", 12).attr("y", y + rowH / 2 + 1).text(S.mode === "lane" ? LANE_NAME[r] : r.length > 21 ? r.slice(0, 20) + "…" : r);
    const n = ev.filter((f) => (S.mode === "lane" ? f.lane : f._dev) === r).length;
    g.rows.append("text").attr("class", "row-count").attr("x", 12).attr("y", y + rowH / 2 + 16).text(`${n} finding${n === 1 ? "" : "s"}`);
  });
  if (refRow) {
    const y = m.t + rows.length * rowH;
    g.rows.append("line").attr("class", "row-line").attr("x1", 8).attr("x2", W - m.r).attr("y1", y).attr("y2", y);
    g.rows.append("text").attr("class", "row-label").attr("x", 12).attr("y", y + rowH / 2 + 1).text("Answer key");
    g.rows.append("text").attr("class", "row-count").attr("x", 12).attr("y", y + rowH / 2 + 16).text("filled = matched");
  }
  g.rows.append("line").attr("class", "row-line").attr("x1", 8).attr("x2", W - m.r).attr("y1", H - m.b).attr("y2", H - m.b);

  // minimap: where the findings are, across the whole case
  const xm = x0.copy();
  const bins = d3.bin().domain(x0.domain()).thresholds(120).value((f) => +f._t)(ev);
  const mh = d3.scaleSqrt().domain([0, d3.max(bins, (b) => b.length) || 1]).range([0, 20]);
  g.mini.selectAll("rect.bin").data(bins.filter((b) => b.length)).join("rect").attr("class", "bin")
    .attr("x", (b) => xm(b.x0)).attr("width", (b) => Math.max(2, xm(b.x1) - xm(b.x0) - 1)).attr("y", (b) => 22 - mh(b.length)).attr("height", (b) => mh(b.length)).attr("rx", 1);
  const brush = d3.brushX().extent([[m.l, 0], [W - m.r, 24]]).on("brush end", (e) => {
    if (!e.sourceEvent || !e.selection) return;
    zoomTo(xm.invert(e.selection[0]), xm.invert(e.selection[1]), 0);
  });
  g.mini.call(brush);

  const zoom = d3.zoom().scaleExtent([1, 40000]).extent([[m.l, 0], [W - m.r, H]]).translateExtent([[m.l, 0], [W - m.r, H]])
    .filter((e) => !e.target.closest?.(".mini") && (!e.button || e.type === "wheel"))
    .on("zoom", (e) => { chart.xz = e.transform.rescaleX(x0); draw(); });
  svg.call(zoom).on("dblclick.zoom", null);

  function zoomTo(a, b, ms = 500) {
    const pa = x0(a), pb = x0(b);
    const k = Math.min(40000, (W - m.l - m.r) / Math.max(1e-6, pb - pa));
    const tr = d3.zoomIdentity.translate(m.l - k * pa, 0).scale(k);
    (ms && !reduced ? svg.transition().duration(ms) : svg).call(zoom.transform, tr);
  }

  function draw() {
    const x = chart.xz, [d0, d1] = x.domain();
    const span = d1 - d0;
    g.axis.call(d3.axisBottom(x).ticks(Math.max(3, Math.floor((W - m.l) / 110))).tickSizeOuter(0)
      .tickFormat((d) => (d.getUTCHours() === 0 && d.getUTCMinutes() === 0 && d.getUTCSeconds() === 0 ? d3.utcFormat("%a %d %b")(d)
        : span > 2 * 3600e3 ? d3.utcFormat("%H:%M")(d) : d3.utcFormat("%H:%M:%S")(d))));
    // day bands and labels
    const days = d3.utcDay.range(d3.utcDay.floor(d0), d1);
    g.days.selectAll("rect").data(days.filter((d, i) => d.getUTCDate() % 2 === 0)).join("rect").attr("class", "dayband")
      .attr("x", (d) => Math.max(m.l, x(d))).attr("width", (d) => Math.max(0, Math.min(W - m.r, x(d3.utcDay.offset(d, 1))) - Math.max(m.l, x(d))))
      .attr("y", m.t).attr("height", H - m.t - m.b);
    g.daylabels.selectAll("text").data(span < 12 * 86400e3 ? days : []).join("text").attr("class", "daylabel")
      .attr("x", (d) => Math.max(m.l + 6, x(d) + 6)).attr("y", 16).text((d) => fDay(d));
    // story ticks
    g.beats.selectAll("line").data(S.tl.beats, (b) => b.id).join("line")
      .attr("class", (b) => `beat-tick ${b.severity >= 2 ? "key" : ""} ${S.tl.keyBeats[S.beat]?.id === b.id ? "cur" : ""}`)
      .attr("x1", (b) => x(wall(b.time))).attr("x2", (b) => x(wall(b.time))).attr("y1", 26).attr("y2", (b) => 26 + 4 + b.severity * 3)
      .on("click", (e, b) => { const i = S.tl.keyBeats.indexOf(b); if (i >= 0) gotoBeat(i, false); else select({ group: b.findings, title: b.title }); })
      .on("mousemove", (e, b) => tip(e, `<b>${h(b.title)}</b><small>${fShort(wall(b.time))}</small>`)).on("mouseleave", () => tip());
    // marks, clustered so nothing hides behind anything else
    const vis = visible();
    const jset = S.journey ? new Set(S.journey.sightings.map((s) => s.finding)) : null;
    const groups = d3.groups(vis.filter((f) => f._t >= d0 - span * 0.02 && f._t <= +d1 + span * 0.02), (f) => rowOf(f) + "|" + (S.mode === "lane" ? "" : f.lane));
    const clusters = [];
    for (const [, fs] of groups) {
      fs.sort((a, b) => a._t - b._t);
      let cur = null;
      for (const f of fs) {
        const px = x(f._t);
        if (cur && px - cur.px0 <= 15) { cur.items.push(f); cur.px1 = px; }
        else { cur = { items: [f], px0: px, px1: px, y: yOf(f) }; clusters.push(cur); }
      }
    }
    const selIds = selectedIds();
    for (const c of clusters) {
      c.x = (c.px0 + c.px1) / 2;
      c.sev = d3.max(c.items, (f) => f.severity);
      c.lane = c.items.reduce((a, b) => (b.severity > a.severity ? b : a)).lane;
      c.sel = c.items.some((f) => selIds.has(f.id));
      c.dim = jset ? !c.items.some((f) => jset.has(f.id)) : false;
      c.key = c.items[0].id;
    }
    g.marks.selectAll("circle").data(clusters, (c) => c.key).join("circle")
      .attr("class", (c) => `mark ${c.sel ? "sel" : ""} ${c.dim ? "dim" : ""}`)
      .attr("cx", (c) => c.x).attr("cy", (c) => c.y).attr("r", (c) => R[c.sev] + (c.items.length > 1 ? 1.5 : 0))
      .attr("fill", (c) => laneColor(c.lane))
      .on("click", (e, c) => select(c.items.length === 1 ? { finding: c.items[0].id } : { group: c.items.map((f) => f.id) }))
      .on("mousemove", (e, c) => tip(e, c.items.length === 1
        ? `<b>${h(c.items[0].title)}</b><small>${fShort(c.items[0]._t)} · ${LANE_NAME[c.items[0].lane]}</small>`
        : `<b>${c.items.length} findings</b> ${h(c.items[0].title)}${c.items.length > 1 ? " and more" : ""}<small>${fShort(c.items[0]._t)} to ${fClock(c.items.at(-1)._t)}</small>`))
      .on("mouseleave", () => tip());
    g.marks.selectAll("text").data(clusters.filter((c) => c.items.length > 1), (c) => c.key).join("text")
      .attr("class", (c) => `count ${c.dim ? "dim" : ""}`).attr("x", (c) => c.x + R[c.sev] + 4).attr("y", (c) => c.y - 5).text((c) => c.items.length);
    // the thread of one file through the case
    const pts = S.journey ? S.journey.sightings.map((s) => byId(s.finding)).filter((f) => f?._t && rowOf(f) >= 0).sort((a, b) => a._t - b._t) : [];
    g.thread.selectAll("path").data(pts.length > 1 ? [pts] : []).join("path").attr("class", "thread")
      .attr("d", d3.line().x((f) => x(f._t)).y((f) => yOf(f)).curve(d3.curveMonotoneX));
    g.thread.selectAll("circle").data(pts).join("circle").attr("class", "thread-dot").attr("r", 11).attr("cx", (f) => x(f._t)).attr("cy", (f) => yOf(f));
    // answer key overlay
    if (refRow) {
      const yr = m.t + rows.length * rowH + rowH / 2, hit = S.tl.score?.matches || {}, seen = new Set(S.tl.score?.examined || []);
      g.ref.selectAll("path").data(S.tl.reference.events, (e) => e.id).join("path")
        .attr("class", (e) => `ref ${hit[e.id] ? "hit" : ""} ${seen.has(e.needs) ? "" : "na"}`)
        .attr("d", d3.symbol(d3.symbolDiamond, 70)()).attr("transform", (e) => `translate(${x(wall(e.time))},${yr})`)
        .on("click", (ev2, e) => select({ ref: e.id }))
        .on("mousemove", (ev2, e) => tip(ev2, `<b>${h(e.title)}</b><small>${fShort(wall(e.time))} · ${hit[e.id] ? "matched by a finding" : seen.has(e.needs) ? "no matching finding" : "that image has not been examined"}</small>`))
        .on("mouseleave", () => tip());
    } else g.ref.selectAll("*").remove();
    // playhead
    const b = S.tl.keyBeats[S.beat];
    g.head.selectAll("line").data(b ? [b] : []).join("line").attr("class", "playhead").attr("x1", (d) => x(wall(d.time))).attr("x2", (d) => x(wall(d.time))).attr("y1", 22).attr("y2", H - m.b);
    g.head.selectAll("path").data(b ? [b] : []).join("path").attr("class", "playhead-cap").attr("d", "M-5,0L5,0L0,7Z").attr("transform", (d) => `translate(${x(wall(d.time))},20)`);
    g.mini.call(brush.move, [Math.max(m.l, xm(d0)), Math.min(W - m.r, xm(d1))]);
  }

  chart = { x0, xz: x0, draw, zoomTo, W, m };
  if (prev) zoomTo(new Date(Math.max(prev[0], x0.domain()[0])), new Date(Math.min(prev[1], x0.domain()[1])), 0);
  else draw();
}

function tip(e, html) {
  const t = $("#tip");
  if (!e) { t.hidden = true; return; }
  t.innerHTML = html; t.hidden = false;
  const box = $("#chartWrap").getBoundingClientRect();
  const x = e.clientX - box.left, y = e.clientY - box.top;
  t.style.left = Math.min(x + 14, box.width - t.offsetWidth - 8) + "px";
  t.style.top = (y > 90 ? y - t.offsetHeight - 12 : y + 18) + "px";
}

function renderEmpty() {
  const e = $("#empty");
  e.hidden = false;
  if (!S.caseId) { e.innerHTML = `<div><h3>No case is open</h3>Create one with New case, or run <code>python -m casereplay demo</code> for the practice case.</div>`; return; }
  const missing = S.tl?.case.images.filter((i) => !i.present) || [];
  e.innerHTML = missing.length === (S.tl?.case.images.length || 0)
    ? `<div><h3>The evidence images are not on this computer yet</h3>Download them, then send the agents. For the NIST case: <code>bash scripts/fetch_dataset.sh</code></div>`
    : `<div><h3>Nothing has been examined yet</h3>Send the agents to examine the evidence. Findings appear here as they come in.</div>`;
}

/* ---------- story and replay ---------- */
function renderCaption() {
  const b = S.tl.keyBeats[S.beat], c = S.tl.case;
  if (!b) {
    const n = S.tl.keyBeats.length;
    $("#caption").innerHTML = `<div class="when">${h(c.name)}</div><h1>${n ? "What happened, in order" : "No account yet"}</h1>
      <p>${n ? `${n} moments across ${S.tl.acts.length} day${S.tl.acts.length === 1 ? "" : "s"}. Press Replay to step through them, or pick anything on the timeline to see the evidence behind it.` : h(c.description || "Send the agents to build the timeline.")}</p>`;
  } else {
    const a = wall(b.time), z = wall(b.time_end);
    $("#caption").innerHTML = `<div class="when"><span><i class="swatch" style="background:${laneColor(b.lane)}"></i>${fDay(a)}, ${fClock(a)}${z - a > 60000 ? " to " + fClock(z) : ""}</span>
      <i>${S.beat + 1} of ${S.tl.keyBeats.length}</i><i>${b.agreement > 1 ? `${b.agreement} agents agree` : "1 agent"}</i></div>
      <h1>${h(b.title)}</h1><p>${h(b.text)}</p>`;
  }
  $("#playBtn").textContent = S.playing ? "Pause" : S.beat >= 0 ? "Resume" : "Replay";
  $("#prevBeat").disabled = S.beat <= 0;
  $("#nextBeat").disabled = S.beat >= S.tl.keyBeats.length - 1;
}

function gotoBeat(i, follow = true) {
  const b = S.tl.keyBeats[i];
  if (!b) return;
  S.beat = i; S.journey = null;
  S.sel = { group: b.findings, beat: b.id };
  if (chart) {
    const [d0, d1] = chart.xz.domain(), t = +wall(b.time);
    let span = d1 - d0;
    if (follow && span > 6 * 3600e3) span = 3 * 3600e3;
    if (follow || t < +d0 + span * 0.08 || t > +d1 - span * 0.08) chart.zoomTo(new Date(t - span * 0.35), new Date(t + span * 0.65), 650);
    else chart.draw();
  }
  renderCaption(); renderExhibit();
}
function stopPlay() { S.playing = false; clearInterval(S.timer); S.timer = null; }
function togglePlay() {
  if (S.playing) { stopPlay(); renderCaption(); return; }
  if (!S.tl?.keyBeats.length) return;
  S.playing = true;
  gotoBeat(S.beat >= S.tl.keyBeats.length - 1 ? 0 : Math.max(0, S.beat + (S.beat < 0 ? 1 : 0)));
  S.timer = setInterval(() => {
    if (S.beat >= S.tl.keyBeats.length - 1) { stopPlay(); renderCaption(); return; }
    gotoBeat(S.beat + 1);
  }, 3400);
}

/* ---------- selection and the exhibit panel ---------- */
function selectedIds() {
  const s = S.sel;
  if (!s) return new Set();
  if (s.finding) return new Set([s.finding]);
  if (s.group) return new Set(s.group);
  return new Set();
}
function select(sel) {
  S.sel = sel;
  if (sel?.journey) S.journey = S.tl.journeys.find((j) => j.id === sel.journey) || null;
  else if (sel?.finding && S.journey && !S.journey.sightings.some((s) => s.finding === sel.finding)) S.journey = null;
  else if (!sel || sel.group || sel.ref) S.journey = sel?.keepJourney ? S.journey : null;
  chart?.draw(); renderExhibit(); renderTab();
}

const proof = (f, e) => `<div class="proof"><div class="src">${h(e.source)}</div><dl>
  <dt>image</dt><dd>${h(e.image)}</dd>
  ${e.path ? `<dt>path</dt><dd>${h(e.path)}</dd>` : ""}
  ${e.offset != null ? `<dt>offset</dt><dd>${e.offset.toLocaleString()} bytes${e.length ? `, length ${e.length.toLocaleString()}` : ""}</dd>` : ""}
  ${e.sha256 ? `<dt>sha-256</dt><dd>${h(e.sha256)}</dd>` : ""}
  ${e.detail ? `<dt>detail</dt><dd>${h(e.detail)}</dd>` : ""}</dl>
  ${e.extracted_to ? `<p style="margin:8px 0 0"><a href="/api/cases/${S.caseId}/recovered/${f.id}">Download the recovered file</a></p>` : ""}</div>`;

const member = (f) => `<li data-f="${f.id}"><i style="background:${laneColor(f.lane)}"></i><span>${h(f.title)}<small>${when(f.time)} · ${h(f.agent)} agent</small></span></li>`;

function renderExhibit() {
  const el = $("#exhibit"), s = S.sel, tl = S.tl;
  if (!tl) { el.innerHTML = ""; return; }
  if (s?.finding && byId(s.finding)) {
    const f = byId(s.finding), j = tl.journeyOf.get(f.id) || (f.data.based_on && tl.journeyOf.get(f.data.based_on));
    const rv = f.review?.status || "unreviewed";
    el.innerHTML = `<div class="kicker"><i style="background:${laneColor(f.lane)}"></i>${LANE_NAME[f.lane]} · ${h(KIND_NAME[f.kind] || f.kind)}</div>
      <h3>${h(f.title)}</h3><p class="sum">${h(f.summary)}</p>
      <dl class="facts"><dt>When</dt><dd>${when(f.time)}${f.time_end ? " to " + fClock(wall(f.time_end)) : ""}${f.time ? `<br><span class="muted">${h(f.time.replace("+00:00", "Z"))} UTC</span>` : ""}</dd>
      ${f.time_source ? `<dt>Time from</dt><dd>${h(f.time_source)}</dd>` : ""}
      <dt>Found by</dt><dd>${h(f.agent)} agent, confidence ${Math.round(f.confidence * 100)}%</dd>
      <dt>Finding</dt><dd><span class="muted" style="font-family:var(--mono);font-size:11.5px">${f.id}</span></dd></dl>
      <div class="chips">${f.entities.map((e) => `<span class="chip ${e.type}">${h(e.label)}</span>`).join("")}</div>
      ${j ? `<button class="primary" data-journey="${j.id}" style="margin-bottom:14px">Follow this file across devices</button>` : ""}
      ${f.data.based_on && byId(f.data.based_on) ? `<h4>Rests on</h4><ul class="members">${member(byId(f.data.based_on))}</ul>` : ""}
      ${f.data.supports ? `<h4>Rests on</h4><ul class="members">${f.data.supports.map(byId).filter(Boolean).map(member).join("")}</ul>` : ""}
      <h4>Evidence, so anyone can check this</h4>${f.evidence.map((e) => proof(f, e)).join("")}
      <div class="review"><span class="state">Review: ${rv}${f.review?.note ? " · " + h(f.review.note) : ""}</span>
        <button data-review="confirmed" ${rv === "confirmed" ? "disabled" : ""}>Confirm</button>
        <button data-review="rejected">Reject</button></div>`;
    el.dataset.finding = f.id;
  } else if (s?.group) {
    const fs = s.group.map(byId).filter(Boolean), b = s.beat && tl.beats.find((x) => x.id === s.beat);
    el.innerHTML = b
      ? `<div class="kicker"><i style="background:${laneColor(b.lane)}"></i>${LANE_NAME[b.lane]} · moment ${S.beat + 1} of ${tl.keyBeats.length}</div>
         <h3>${h(b.title)}</h3><p class="sum">${h(b.text)}</p>
         <dl class="facts"><dt>When</dt><dd>${when(b.time)}</dd><dt>Backed by</dt><dd>${b.agents.map(h).join(", ")} (${b.agreement} agent${b.agreement === 1 ? "" : "s"})</dd>
         <dt>Certainty</dt><dd>lowest confidence in this group ${Math.round(b.confidence * 100)}%</dd></dl>
         <h4>${fs.length} finding${fs.length === 1 ? "" : "s"} behind this</h4><ul class="members">${fs.map(member).join("")}</ul>`
      : `<div class="kicker">${fs.length} findings at this point</div><h3>${h(s.title || "Pick one to see its evidence")}</h3><ul class="members">${fs.map(member).join("")}</ul>`;
  } else if (s?.journey && S.journey) {
    const j = S.journey, fake = j.names.filter((n) => n !== j.true_name);
    el.innerHTML = `<div class="kicker">One file, every place it was seen</div><h3>${h(j.label)}</h3>
      <p class="sum">${j.true_type || "File"}${j.inner_title ? `. Inside, it reads: “${h(j.inner_title.slice(0, 110))}”` : ""}. Seen on ${j.devices.length} device${j.devices.length === 1 ? "" : "s"}${fake.length && j.true_name ? ` and under ${fake.length} false name${fake.length === 1 ? "" : "s"}: ${fake.map(h).join(", ")}` : ""}.</p>
      <dl class="facts"><dt>Matched by</dt><dd>${j.link ? "identical content (hash)" : "single copy"}</dd><dt>sha-256</dt><dd><span style="font-family:var(--mono);font-size:11.5px">${j.sha256}</span></dd></dl>
      <h4>Sightings, in time order</h4><ul class="members">${j.sightings.map((x) => `<li data-f="${x.finding}"><i style="background:${x.disguised ? laneColor("coverup") : laneColor("files")}"></i>
        <span>${h(x.device)}: ${h(x.named ? x.name : "unnamed copy")}<small>${x.state === "live" ? "still on the device" : x.state === "carved" ? "carved from raw data" : "deleted, recovered"}${x.disguised ? " · false name" : ""} · ${when(x.time)}</small></span></li>`).join("")}</ul>`;
  } else if (s?.ref) {
    const e = tl.reference.events.find((x) => x.id === s.ref), hit = tl.score?.matches?.[e.id];
    el.innerHTML = `<div class="kicker">Answer key · ${h(tl.reference.name)}</div><h3>${h(e.title)}</h3>
      <dl class="facts"><dt>When</dt><dd>${when(e.time)}</dd><dt>Status</dt><dd>${hit ? "matched by a finding" : (tl.score.examined || []).includes(e.needs) ? "no matching finding yet" : "needs an image that has not been examined"}</dd></dl>
      ${hit && byId(hit) ? `<h4>Matching finding</h4><ul class="members">${member(byId(hit))}</ul>` : ""}
      <p class="muted">${h(tl.reference.note || "")}</p>`;
  } else {
    const st = tl.stats;
    el.innerHTML = `<div class="placeholder"><h3>${h(tl.case.name)}</h3><p>${h(tl.case.description)}</p>
      <p>Pick any point on the timeline to see what was found and the exact evidence behind it: which image, where in it, and its hash.</p>
      ${st.findings ? `<p>${st.findings} findings from ${st.agents.length} agents. ${st.confirmed} confirmed by a reviewer, ${st.rejected} rejected.</p>` : ""}</div>`;
  }
}

/* ---------- tabs ---------- */
function md(text) {
  const out = [];
  let list = false;
  for (const raw of text.split("\n")) {
    let line = h(raw).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/\bf_[0-9a-f]{12}\b/g, (id) => `<span class="cite" data-f="${id}">${id}</span>`);
    const li = /^\s*[-*]\s+/.test(raw);
    if (li && !list) { out.push("<ul>"); list = true; }
    if (!li && list) { out.push("</ul>"); list = false; }
    if (/^#\s/.test(raw)) out.push(`<h3 style="font-size:20px">${line.replace(/^#\s/, "")}</h3>`);
    else if (/^#{2,}\s/.test(raw)) out.push(`<h3>${line.replace(/^#+\s/, "")}</h3>`);
    else if (li) out.push(`<li>${line.replace(/^\s*[-*]\s+/, "")}</li>`);
    else if (raw.trim()) out.push(`<p>${line}</p>`);
  }
  if (list) out.push("</ul>");
  return out.join("");
}

async function renderTab() {
  const el = $("#tabpane"), tl = S.tl;
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === S.tab));
  if (!tl) { el.innerHTML = ""; return; }
  if (S.tab === "files") {
    const js = tl.journeys.filter((j) => j.notable);
    el.innerHTML = js.length ? `<table><thead><tr><th>Document</th><th>Really is</th><th>Where it went</th></tr></thead><tbody>${js.map((j) => `
      <tr class="pick ${S.journey?.id === j.id ? "cur" : ""}" data-journey="${j.id}"><td><b>${h(j.label)}</b>${j.inner_title && !j.true_name ? `<br><span class="muted">“${h(j.inner_title.slice(0, 70))}”</span>` : ""}</td>
      <td>${h(j.true_type || "")}</td><td><span class="path">${j.sightings.map((s) => `<span class="stop ${s.state} ${s.disguised ? "false" : ""}">${h(s.device)} <small>${h(s.named ? s.name : "unnamed")}${s.state === "live" ? "" : s.state === "carved" ? ", carved" : ", deleted"}</small></span>`).join('<span class="arrow">then</span>')}</span></td></tr>`).join("")}</tbody></table>
      <p class="muted" style="margin-top:10px">Dashed boxes were deleted or carved back. A red outline marks a false name. Pick a row to draw the file's thread on the timeline.</p>`
      : `<p class="muted">No files have been traced yet. Send the intake, recovery and disguise agents.</p>`;
  } else if (S.tab === "points") {
    const und = d3.rollups(tl.undated, (v) => v.length, (f) => f.kind).sort((a, b) => b[1] - a[1]);
    el.innerHTML = (tl.cautions.length ? `<table><thead><tr><th>Kind</th><th>What needs attention</th></tr></thead><tbody>${tl.cautions.map((c) => `<tr class="pick" data-f="${c.finding}"><td>${h(c.level)}</td><td>${h(c.text)}</td></tr>`).join("")}</tbody></table>`
      : `<p>Nothing contradicts the timeline so far.</p>`) +
      (und.length ? `<h4 style="margin:18px 0 6px;font:600 12px var(--sans);color:var(--ink-2)">Findings with no reliable time (kept off the timeline)</h4><table><tbody>${und.map(([k, n]) => `<tr class="pick" data-kind="${k}"><td class="num" style="width:50px">${n}</td><td>${h(KIND_NAME[k] || k)}</td></tr>`).join("")}</tbody></table>` : "");
  } else if (S.tab === "score" && tl.score) {
    const sc = tl.score;
    el.innerHTML = `<p>Checked against <b>${h(sc.reference)}</b>. The answer key is read only by the scorer. No agent sees it.
      ${sc.overall != null ? `Overall: <b>${Math.round(sc.overall * 100)}%</b> of the items that could be checked.` : ""}</p>
      <table><thead><tr><th>Check</th><th>Result</th><th>Missed</th></tr></thead><tbody>${sc.checks.map((c) => `<tr><td>${h(c.label)}${c.note ? `<br><span class="muted">${h(c.note)}</span>` : ""}</td>
      <td style="white-space:nowrap">${c.ran ? `<span class="meter"><i style="width:${Math.round(100 * c.found / Math.max(1, c.expected))}%"></i></span>${c.found} of ${c.expected}` : '<span class="muted">not run yet</span>'}</td>
      <td class="muted">${c.ran ? h(c.missed.slice(0, 6).join("; ")) + (c.missed.length > 6 ? ` and ${c.missed.length - 6} more` : "") : ""}</td></tr>`).join("")}</tbody></table>`;
  } else if (S.tab === "findings") {
    const fs = [...visible(), ...tl.undated.filter((f) => f.severity >= S.sev)].slice(0, 600);
    el.innerHTML = `<table><thead><tr><th>Time</th><th>Lane</th><th>Finding</th><th>Agent</th><th>Review</th></tr></thead><tbody>${fs.map((f) => `<tr class="pick ${S.sel?.finding === f.id ? "cur" : ""}" data-f="${f.id}">
      <td style="white-space:nowrap">${f.time ? fShort(wall(f.time)) : '<span class="muted">none</span>'}</td><td><i style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${laneColor(f.lane)};margin-right:6px"></i>${LANE_NAME[f.lane]}</td>
      <td>${h(f.title)}</td><td>${h(f.agent)}</td><td>${h(f.review?.status === "unreviewed" ? "" : f.review?.status || "")}</td></tr>`).join("")}</tbody></table>`;
  } else if (S.tab === "report") {
    const text = tl.report || (await api(`/api/cases/${S.caseId}/report`));
    el.innerHTML = `<p class="muted">${tl.report ? `Written by the lead investigator (${h(tl.lead?.model || "LLM")}). Every claim cites findings in the ledger.` : "Assembled from the agreed timeline without a language model. Each line cites the findings behind it."}</p><div class="narrative">${md(text)}</div>`;
  }
}

/* ---------- events ---------- */
function bind() {
  $("#caseSelect").addEventListener("change", (e) => openCase(e.target.value));
  $("#sendAll").addEventListener("click", () => send(null));
  $("#evidence").addEventListener("change", (e) => {
    const id = e.target.dataset?.image;
    if (id) e.target.checked ? S.skip.delete(id) : S.skip.add(id);
  });
  $("#agents").addEventListener("click", (e) => { const a = e.target.dataset?.agent; if (a) send([a]); });
  $("#playBtn").addEventListener("click", togglePlay);
  $("#prevBeat").addEventListener("click", () => { stopPlay(); gotoBeat(S.beat - 1, false); });
  $("#nextBeat").addEventListener("click", () => { stopPlay(); gotoBeat(S.beat + 1, false); });
  const seg = (id, key, attr, after) => $(id).addEventListener("click", (e) => {
    const v = e.target.dataset?.[attr];
    if (!v) return;
    S[key] = attr === "sev" ? +v : v;
    $(id).querySelectorAll("button").forEach((b) => { b.classList.toggle("on", b === e.target); b.setAttribute("aria-checked", b === e.target); });
    after();
  });
  seg("#modeSeg", "mode", "mode", () => buildChart(false));
  seg("#sevSeg", "sev", "sev", () => { chart?.draw(); renderTab(); refresh3d(); });
  $("#search").addEventListener("input", (e) => { S.q = e.target.value.trim().toLowerCase(); chart?.draw(); if (S.tab === "findings") renderTab(); refresh3d(); });
  $("#refToggle").addEventListener("change", (e) => { S.showRef = e.target.checked; buildChart(false); });
  $("#legend").addEventListener("click", (e) => {
    const l = e.target.closest("button")?.dataset.lane;
    if (!l) return;
    S.hidden.has(l) ? S.hidden.delete(l) : S.hidden.add(l);
    renderLegend(); chart?.draw(); if (S.tab === "findings") renderTab(); refresh3d();
  });
  $("#days").addEventListener("click", (e) => {
    const a = S.tl.acts.find((x) => x.day === e.target.dataset?.day);
    if (!a || !chart) return;
    const s = +wall(a.start), z = +wall(a.end), pad = Math.max((z - s) * 0.08, 10 * 60000);
    chart.zoomTo(new Date(s - pad), new Date(z + pad));
  });
  $("#fitBtn").addEventListener("click", () => chart && chart.zoomTo(...chart.x0.domain()));
  document.querySelector(".tabs").addEventListener("click", (e) => { if (e.target.dataset?.tab) { S.tab = e.target.dataset.tab; renderTab(); } });
  $("#tabpane").addEventListener("click", (e) => {
    const row = e.target.closest("[data-journey],[data-f],[data-kind]");
    if (!row) return;
    if (row.dataset.journey) select({ journey: row.dataset.journey });
    else if (row.dataset.f && byId(row.dataset.f)) focusFinding(row.dataset.f);
    else if (row.dataset.kind) select({ group: S.tl.undated.filter((f) => f.kind === row.dataset.kind).map((f) => f.id), title: KIND_NAME[row.dataset.kind] || row.dataset.kind });
  });
  $("#exhibit").addEventListener("click", async (e) => {
    const t = e.target.closest("[data-f],[data-journey],[data-review]");
    if (!t) return;
    if (t.dataset.f) focusFinding(t.dataset.f, true);
    else if (t.dataset.journey) select({ journey: t.dataset.journey });
    else if (t.dataset.review) {
      const id = $("#exhibit").dataset.finding;
      const note = t.dataset.review === "rejected" ? prompt("Why is this finding rejected? (kept in the case log)") ?? "" : "";
      await api(`/api/cases/${S.caseId}/review`, { finding_id: id, status: t.dataset.review, note });
      const keep = t.dataset.review === "rejected" ? null : { finding: id };
      await loadTimeline(false);
      select(keep);
    }
  });
  $("#newCaseBtn").addEventListener("click", () => $("#newCase").showModal());
  $("#newCase").addEventListener("close", async () => {
    if ($("#newCase").returnValue !== "ok") return;
    const fd = new FormData($("#newCaseForm"));
    const images = String(fd.get("images")).split("\n").map((l) => l.split(",").map((x) => x.trim())).filter((p) => p.length >= 4)
      .map(([id, kind, label, ...path]) => ({ id, kind, label, path: path.join(",") }));
    try {
      const c = await api("/api/cases", { name: fd.get("name"), timezone: fd.get("timezone"), images });
      S.cases = await api("/api/cases");
      $("#caseSelect").innerHTML = S.cases.map((x) => `<option value="${h(x.id)}">${h(x.name)}</option>`).join("");
      $("#caseSelect").value = c.id;
      await openCase(c.id);
    } catch (err) { alert(err.message); }
  });
  $("#view3d").addEventListener("click", async () => {
    S.mod3d = S.mod3d || (await import("/static/replay3d.js").catch(() => null));
    if (!S.mod3d) { alert("The 3D view could not be loaded."); return; }
    S.view3d = !S.view3d;
    $("#view3d").textContent = S.view3d ? "Flat view" : "3D view";
    $("#chart").toggleAttribute("hidden", S.view3d); $("#chart3d").toggleAttribute("hidden", !S.view3d);
    if (S.view3d) refresh3d(); else S.mod3d.hide();
  });
  let rz;
  window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => S.tl && buildChart(false), 150); });
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, textarea, select")) return;
    if (e.key === "ArrowRight") { stopPlay(); gotoBeat(Math.min(S.tl.keyBeats.length - 1, S.beat + 1), false); }
    if (e.key === "ArrowLeft") { stopPlay(); gotoBeat(Math.max(0, S.beat - 1), false); }
    if (e.key === " ") { e.preventDefault(); togglePlay(); }
  });
}

function refresh3d() {
  if (S.view3d && S.mod3d && S.tl?.events.length) S.mod3d.show($("#chart3d"), S, { wall, laneColor, LANES, LANE_NAME, select, visible });
}

function focusFinding(id, keepJourney) {
  const f = byId(id);
  if (!f) return;
  const j = keepJourney ? S.journey : null;
  S.sel = { finding: id }; S.journey = j;
  if (f._t && chart) {
    const [d0, d1] = chart.xz.domain(), span = d1 - d0;
    if (f._t < d0 || f._t > d1) chart.zoomTo(new Date(+f._t - span / 2), new Date(+f._t + span / 2));
  }
  chart?.draw(); renderExhibit(); renderTab();
}

boot().catch((e) => { document.body.insertAdjacentHTML("beforeend", `<pre style="padding:20px;color:#b00">${h(e.stack || e)}</pre>`); });
