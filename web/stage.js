// The enclave, drawn in three.js on a transparent overlay that spans the page.
// Objects live in screen pixels (orthographic camera), so data can fly from a
// real DOM row into the cube and back out to another row, and everything
// follows the page as it scrolls.

import * as THREE from "https://cdn.jsdelivr.net/npm/three@0.170.0/build/three.module.js";

const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const easeOut = (t) => 1 - Math.pow(1 - t, 3);

function rectCenter(el) {
  const r = el.getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2, r };
}

export class Stage {
  constructor() {
    this.canvas = document.createElement("canvas");
    this.canvas.className = "overlay";
    this.canvas.setAttribute("aria-hidden", "true");
    document.body.appendChild(this.canvas);
    this.renderer = new THREE.WebGLRenderer({ canvas: this.canvas, antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    this.scene = new THREE.Scene();
    this.camera = new THREE.OrthographicCamera(0, 1, 0, -1, -2000, 2000);
    this.tasks = new Set(); // per-frame animations
    this.anchorEl = null;
    this.state = "pending";
    this.energy = 0; // 0 idle, 1 working
    this.pulse = 0;
    this.colors();
    this.build();
    addEventListener("resize", () => this.resize());
    matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => this.colors(true));
    this.resize();
    this.t0 = performance.now();
    this.renderer.setAnimationLoop((t) => this.frame(t));
  }

  colors(refresh = false) {
    this.c = {
      ink: new THREE.Color(css("--ink")),
      teal: new THREE.Color(css("--teal")),
      ox: new THREE.Color(css("--oxblood")),
      rule: new THREE.Color(css("--rule")),
      redact: new THREE.Color(css("--redact")),
    };
    if (refresh) this.applyState();
  }

  build() {
    const S = 100;
    this.size = S;
    this.root = new THREE.Group();
    this.scene.add(this.root);

    // Outer shell: the enclave boundary, drawn in itself on load.
    const shell = new THREE.EdgesGeometry(new THREE.BoxGeometry(S, S, S));
    this.shellMat = new THREE.LineBasicMaterial({ color: this.c.ink, transparent: true });
    this.shell = new THREE.LineSegments(shell, this.shellMat);
    this.shell.geometry.setDrawRange(0, reduced ? Infinity : 0);
    this.root.add(this.shell);

    this.faceMat = new THREE.MeshBasicMaterial({ color: this.c.ink, transparent: true, opacity: 0.06, depthWrite: false });
    this.root.add(new THREE.Mesh(new THREE.BoxGeometry(S, S, S), this.faceMat));

    // Inner lattice: measured memory, the part attestation covers.
    this.latticeMat = new THREE.LineBasicMaterial({ color: this.c.rule, transparent: true, opacity: 0.9 });
    const lattice = new THREE.Group();
    for (const k of [-1, 0, 1]) {
      const g = new THREE.EdgesGeometry(new THREE.BoxGeometry(S * 0.62, S * 0.02, S * 0.62));
      const m = new THREE.LineSegments(g, this.latticeMat);
      m.position.y = k * S * 0.22;
      lattice.add(m);
    }
    this.root.add(lattice);

    // Core: spins up while the model is working.
    this.coreMat = new THREE.MeshBasicMaterial({ color: this.c.ink, wireframe: true, transparent: true, opacity: 0.55 });
    this.core = new THREE.Mesh(new THREE.IcosahedronGeometry(S * 0.17, 1), this.coreMat);
    this.root.add(this.core);

    // Attestation ring.
    const ringPts = [];
    for (let i = 0; i <= 128; i++) {
      const a = (i / 128) * Math.PI * 2;
      ringPts.push(new THREE.Vector3(Math.cos(a) * S * 0.95, 0, Math.sin(a) * S * 0.95));
    }
    this.ringMat = new THREE.LineDashedMaterial({ color: this.c.rule, dashSize: 6, gapSize: 5, transparent: true });
    this.ring = new THREE.Line(new THREE.BufferGeometry().setFromPoints(ringPts), this.ringMat);
    this.ring.computeLineDistances();
    this.ringGroup = new THREE.Group();
    this.ringGroup.add(this.ring);
    this.ringGroup.rotation.x = 0.42;
    this.scene.add(this.ringGroup);

    // The seal: a translucent wall between the enclave and the library (agent view only).
    this.wallMat = new THREE.MeshBasicMaterial({ color: this.c.ox, transparent: true, opacity: 0, side: THREE.DoubleSide, depthWrite: false });
    this.wall = new THREE.Mesh(new THREE.PlaneGeometry(S * 0.08, S * 1.9), this.wallMat);
    this.wallEdge = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(S * 0.08, S * 1.9)),
      new THREE.LineBasicMaterial({ color: this.c.ox, transparent: true, opacity: 0 }));
    this.scene.add(this.wall, this.wallEdge);
    this.wallOn = 0;

    this.root.rotation.set(-0.5, 0.7, 0);
    this.drawIn = reduced ? 1 : 0;
  }

  resize() {
    const w = innerWidth, h = innerHeight;
    this.renderer.setSize(w, h, false);
    Object.assign(this.camera, { left: 0, right: w, top: 0, bottom: -h });
    this.camera.updateProjectionMatrix();
  }

  // Where the enclave sits: the centre of this element.
  anchor(el, { wall = false } = {}) {
    this.anchorEl = el;
    this.wallTarget = wall ? 1 : 0;
  }

  setState(state) {
    this.state = state;
    this.applyState();
  }

  applyState() {
    const col = { ok: this.c.teal, bad: this.c.ox }[this.state] || this.c.rule;
    this.ringMat.color.copy(col);
    this.shellMat.color.copy(this.c.ink);
    this.latticeMat.color.copy(this.state === "ok" ? this.c.teal : this.c.rule);
    this.coreMat.color.copy(this.c.ink);
    this.faceMat.color.copy(this.c.ink);
  }

  working(on) { this.energyTarget = on ? 1 : 0; }

  center() {
    if (!this.anchorEl || !this.anchorEl.offsetParent) return null;
    const { x, y } = rectCenter(this.anchorEl);
    return new THREE.Vector3(x, -y, 0);
  }

  frame(now) {
    const t = (now - this.t0) / 1000;
    const dt = Math.min(0.05, (now - (this.last || now)) / 1000);
    this.last = now;
    const c = this.center();
    const visible = !!c;
    this.root.visible = this.ringGroup.visible = visible;
    this.wall.visible = this.wallEdge.visible = visible;
    if (visible) {
      this.root.position.copy(c);
      this.ringGroup.position.copy(c);
      const br = this.anchorEl.getBoundingClientRect();
      this.fit = Math.max(0.7, Math.min(1.5, Math.min(br.width, br.height) / 230));
      this.ringGroup.scale.setScalar(this.fit);
      this.wall.scale.setScalar(this.fit); this.wallEdge.scale.setScalar(this.fit);
      this.wall.position.set(c.x + this.size * 1.2 * this.fit, c.y, 50);
      this.wallEdge.position.copy(this.wall.position);
    }

    this.energy += ((this.energyTarget || 0) - this.energy) * Math.min(1, dt * 3);
    this.pulse = Math.max(0, this.pulse - dt * 2.2);
    this.wallOn += ((this.wallTarget || 0) - this.wallOn) * Math.min(1, dt * 4);
    this.wallFlash = Math.max(0, (this.wallFlash || 0) - dt * 1.8);
    this.wallMat.opacity = 0.1 * this.wallOn + 0.4 * this.wallFlash;
    this.wallEdge.material.opacity = 0.8 * this.wallOn;

    if (this.drawIn < 1) {
      this.drawIn = Math.min(1, this.drawIn + dt / 1.4);
      this.shell.geometry.setDrawRange(0, Math.floor(ease(this.drawIn) * 24));
    }
    if (!reduced) {
      this.root.rotation.y += dt * (0.18 + this.energy * 1.6);
      this.root.rotation.x = -0.5 + Math.sin(t * 0.4) * 0.05;
      this.core.rotation.x += dt * (0.3 + this.energy * 4);
      this.core.rotation.z += dt * (0.2 + this.energy * 3);
      this.ring.rotation.y -= dt * (0.25 + this.energy * 1.2);
    }
    const s = 1 + this.pulse * 0.08 + this.energy * Math.sin(t * 9) * 0.02;
    this.root.scale.setScalar(s * (this.fit || 1));
    this.core.scale.setScalar(1 + this.energy * 0.5 + this.pulse * 0.6);
    this.coreMat.opacity = 0.45 + this.energy * 0.45;

    for (const task of [...this.tasks]) if (task(dt) === false) this.tasks.delete(task);
    this.renderer.render(this.scene, this.camera);
  }

  // Fragments of each element fly into the enclave. Resolves when they're in.
  absorb(elements, { perEl = 7, spread = 0.9 } = {}) {
    const c0 = this.center();
    if (!c0 || reduced) { this.pulse = 1; return Promise.resolve(); }
    return new Promise((done) => {
      const parts = [];
      elements.forEach((el, i) => {
        const r = el.getBoundingClientRect();
        for (let k = 0; k < perEl; k++) {
          const w = 4 + Math.random() * 10, h = Math.max(3, r.height * 0.42);
          const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h),
            new THREE.MeshBasicMaterial({ color: this.c.redact, transparent: true }));
          const start = new THREE.Vector3(r.left + Math.random() * r.width, -(r.top + r.height / 2), 10);
          m.position.copy(start);
          this.scene.add(m);
          parts.push({ m, start, delay: i * 0.045 * spread + Math.random() * 0.25, t: 0, bend: (Math.random() - 0.5) * 260, spin: (Math.random() - 0.5) * 8 });
        }
      });
      let landed = 0;
      this.tasks.add((dt) => {
        const c = this.center() || c0;
        for (const p of parts) {
          if (p.done) continue;
          if (p.delay > 0) { p.delay -= dt; continue; }
          p.t = Math.min(1, p.t + dt / 1.1);
          const e = ease(p.t);
          const mid = new THREE.Vector3((p.start.x + c.x) / 2, (p.start.y + c.y) / 2 + p.bend, 10);
          const a = p.start.clone().lerp(mid, e), b = mid.clone().lerp(c, e);
          p.m.position.copy(a.lerp(b, e));
          p.m.rotation.z += p.spin * dt;
          p.m.scale.setScalar(1 - e * 0.75);
          if (p.t >= 1) {
            p.done = true; landed++;
            this.scene.remove(p.m); p.m.geometry.dispose();
            this.pulse = Math.min(1, this.pulse + 0.08);
          }
        }
        if (landed === parts.length) { done(); return false; }
      });
    });
  }

  // Beams from the enclave out to the matched rows. Lines stay, faintly, so the
  // match stays visibly tied to the enclave.
  beams(elements) {
    this.clearBeams();
    if (!elements.length || !this.center()) return Promise.resolve();
    return new Promise((done) => {
      const beams = elements.map((el, i) => {
        const geo = new THREE.BufferGeometry().setFromPoints(Array.from({ length: 33 }, () => new THREE.Vector3()));
        const line = new THREE.Line(geo, new THREE.LineBasicMaterial({ color: this.c.ox, transparent: true }));
        const dot = new THREE.Mesh(new THREE.CircleGeometry(4, 16), new THREE.MeshBasicMaterial({ color: this.c.ox, transparent: true }));
        this.scene.add(line, dot);
        return { el, line, dot, t: reduced ? 1 : -i * 0.18 };
      });
      this.beamSet = beams;
      const host = this.anchorEl;
      let finished = false;
      this.tasks.add((dt) => {
        if (this.beamSet !== beams) return false;
        const c = this.center();
        const show = !!c && this.anchorEl === host;
        for (const b of beams) b.line.visible = b.dot.visible = show;
        if (!show) return;
        let all = true;
        for (const b of beams) {
          b.t = Math.min(1, b.t + dt / 0.9);
          const r = b.el.getBoundingClientRect();
          const toLeft = r.left + r.width / 2 < c.x;
          const end = new THREE.Vector3(toLeft ? r.right + 6 : r.left - 6, -(r.top + r.height / 2), 5);
          const pos = b.line.geometry.attributes.position;
          const k = easeOut(Math.max(0, b.t));
          for (let i = 0; i <= 32; i++) {
            const u = (i / 32) * k;
            const ctrl = new THREE.Vector3((c.x + end.x) / 2, Math.max(c.y, end.y) + 70, 5);
            const p = c.clone().lerp(ctrl, u).lerp(ctrl.clone().lerp(end, u), u);
            pos.setXYZ(i, p.x, p.y, p.z);
          }
          pos.needsUpdate = true;
          const tip = new THREE.Vector3(pos.getX(32), pos.getY(32), 6);
          b.dot.position.copy(tip);
          b.line.material.opacity = b.t >= 1 ? 0.35 : 0.9;
          b.dot.material.opacity = b.t >= 1 ? 0.6 : 1;
          if (b.t < 1) all = false;
        }
        if (all && !finished) { finished = true; done(); }
      });
    });
  }

  clearBeams() {
    for (const b of this.beamSet || []) { this.scene.remove(b.line, b.dot); b.line.geometry.dispose(); }
    this.beamSet = null;
  }

  // A block leaves the enclave and lands on the ledger.
  drop(targetEl) {
    const c0 = this.center();
    if (!c0 || reduced || !targetEl.offsetParent) return Promise.resolve();
    return new Promise((done) => {
      const box = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(22, 22, 22)),
        new THREE.LineBasicMaterial({ color: this.c.teal }));
      box.position.copy(c0);
      this.scene.add(box);
      let t = 0;
      this.tasks.add((dt) => {
        t = Math.min(1, t + dt / 0.9);
        const c = this.center() || c0;
        if (!targetEl.offsetParent) { this.scene.remove(box); done(); return false; }
        const { x, y } = rectCenter(targetEl);
        const end = new THREE.Vector3(x, -y, 20);
        box.position.copy(c.clone().lerp(end, ease(t)));
        box.rotation.x += dt * 5; box.rotation.y += dt * 4;
        if (t >= 1) { this.scene.remove(box); done(); return false; }
      });
    });
  }

  // One read in the agent view: through into the enclave, or shattered on the wall.
  read(fromEl, allowed) {
    const c0 = this.center();
    if (!c0 || reduced) { if (allowed) this.pulse = 1; return Promise.resolve(); }
    return new Promise((done) => {
      const r = fromEl.getBoundingClientRect();
      const start = new THREE.Vector3(r.left - 2, -(r.top + 22), 10);
      const doc = new THREE.Mesh(new THREE.PlaneGeometry(16, 20), new THREE.MeshBasicMaterial({ color: this.c.ink, transparent: true }));
      const docEdge = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(16, 20)), new THREE.LineBasicMaterial({ color: this.c.ink }));
      doc.add(docEdge);
      doc.position.copy(start);
      this.scene.add(doc);
      let t = 0, shards = null;
      this.tasks.add((dt) => {
        const c = this.center() || c0;
        if (!shards) {
          t = Math.min(1, t + dt / 0.8);
          const stop = allowed ? 1 : 0.82;
          const e = ease(Math.min(t / stop, 1));
          const target = allowed ? c : new THREE.Vector3(this.wall.position.x, c.y, 10);
          doc.position.copy(start.clone().lerp(target, e));
          doc.rotation.z = e * 0.6;
          if (allowed) doc.scale.setScalar(1 - e * 0.7);
          if (e >= 1) {
            this.scene.remove(doc);
            if (allowed) { this.pulse = 1; done(); return false; }
            this.wallFlash = 1;
            shards = Array.from({ length: 14 }, () => {
              const m = new THREE.Mesh(new THREE.PlaneGeometry(4 + Math.random() * 5, 3 + Math.random() * 4),
                new THREE.MeshBasicMaterial({ color: this.c.ox, transparent: true }));
              m.position.copy(target);
              this.scene.add(m);
              return { m, v: new THREE.Vector2(40 + Math.random() * 160, (Math.random() - 0.5) * 220), s: (Math.random() - 0.5) * 12 };
            });
          }
          return;
        }
        let alive = false;
        for (const s of shards) {
          s.m.position.x += s.v.x * dt; s.m.position.y += s.v.y * dt; s.v.y -= 260 * dt;
          s.m.rotation.z += s.s * dt;
          s.m.material.opacity = Math.max(0, s.m.material.opacity - dt * 1.3);
          if (s.m.material.opacity > 0) alive = true;
        }
        if (!alive) { shards.forEach((s) => this.scene.remove(s.m)); done(); return false; }
      });
    });
  }
}
