// Nightwatch — Cyber Defense Command hero scene.
// Framework-agnostic: call initHero(canvas) and keep the returned cleanup.
// Works standalone (importmap resolves "three") or in React/bundlers (npm i three).
import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';

export function initHero(canvas) {
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  } catch (e) {
    throw e;
  }
  const W = () => canvas.clientWidth || window.innerWidth;
  const H = () => canvas.clientHeight || window.innerHeight;
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(W(), H(), false);
  renderer.setClearColor(0x000000, 0);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.15;
  renderer.outputColorSpace = THREE.SRGBColorSpace;

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x05070d, 0.045);

  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;

  const camera = new THREE.PerspectiveCamera(42, W() / H(), 0.1, 100);

  // ---- Lighting ----
  scene.add(new THREE.AmbientLight(0x223355, 0.6));
  const keyLight = new THREE.PointLight(0x0a84ff, 60, 60);
  keyLight.position.set(0, 0, 0);
  scene.add(keyLight);
  const cyanLight = new THREE.PointLight(0x32d6ff, 25, 40);
  cyanLight.position.set(6, 4, 6);
  scene.add(cyanLight);
  const fillLight = new THREE.DirectionalLight(0xffffff, 0.8);
  fillLight.position.set(-5, 6, 4);
  scene.add(fillLight);

  const COL_BLUE = 0x0a84ff, COL_CYAN = 0x32d6ff, COL_WHITE = 0xeaf4ff;

  // ---- Central Security Core ----
  const core = new THREE.Group();
  scene.add(core);

  const crystalMat = new THREE.MeshPhysicalMaterial({
    color: COL_BLUE, metalness: 0.1, roughness: 0.12,
    transparent: true, opacity: 0.28, emissive: COL_BLUE, emissiveIntensity: 0.7,
    clearcoat: 1, clearcoatRoughness: 0.1, side: THREE.FrontSide,
  });
  const crystal = new THREE.Mesh(new THREE.IcosahedronGeometry(1.25, 3), crystalMat);
  core.add(crystal);

  const facetMat = new THREE.MeshBasicMaterial({
    color: COL_CYAN, wireframe: true, transparent: true, opacity: 0.18,
    blending: THREE.AdditiveBlending, depthWrite: false,
  });
  const facets = new THREE.Mesh(new THREE.IcosahedronGeometry(1.27, 2), facetMat);
  core.add(facets);

  const innerGlow = new THREE.Mesh(
    new THREE.SphereGeometry(0.55, 32, 32),
    new THREE.MeshBasicMaterial({ color: 0x9fd2ff, transparent: true,
      opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false })
  );
  core.add(innerGlow);

  const pulseRings = [];
  for (let i = 0; i < 3; i++) {
    const ring = new THREE.Mesh(
      new THREE.RingGeometry(1.3, 1.42, 64),
      new THREE.MeshBasicMaterial({ color: COL_CYAN, transparent: true,
        opacity: 0.0, side: THREE.DoubleSide, blending: THREE.AdditiveBlending,
        depthWrite: false })
    );
    ring.rotation.x = Math.PI / 2 + (i * 0.6);
    ring.rotation.y = i * 0.9;
    ring.userData.phase = i / 3;
    core.add(ring);
    pulseRings.push(ring);
  }

  const coreParticles = (() => {
    const n = 260, pos = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
      const r = Math.cbrt(Math.random()) * 1.1;
      const th = Math.random() * Math.PI * 2, ph = Math.acos(2 * Math.random() - 1);
      pos[i*3]   = r * Math.sin(ph) * Math.cos(th);
      pos[i*3+1] = r * Math.cos(ph);
      pos[i*3+2] = r * Math.sin(ph) * Math.sin(th);
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    return new THREE.Points(g, new THREE.PointsMaterial({
      color: COL_WHITE, size: 0.035, transparent: true, opacity: 0.8,
      blending: THREE.AdditiveBlending, depthWrite: false }));
  })();
  core.add(coreParticles);

  // ---- Orbital Defense Rings ----
  const rings = [];
  const ringDefs = [
    { r: 2.3, tube: 0.018, speed: 0.18, axis: 'x', color: COL_BLUE },
    { r: 2.95, tube: 0.016, speed: -0.12, axis: 'y', color: COL_CYAN },
    { r: 3.6, tube: 0.014, speed: 0.09, axis: 'z', color: COL_WHITE },
  ];
  ringDefs.forEach((d) => {
    const g = new THREE.Group();
    const torus = new THREE.Mesh(
      new THREE.TorusGeometry(d.r, d.tube, 16, 220),
      new THREE.MeshStandardMaterial({ color: d.color, emissive: d.color,
        emissiveIntensity: 0.9, metalness: 0.9, roughness: 0.25,
        transparent: true, opacity: 0.55 })
    );
    g.add(torus);
    const bead = new THREE.Mesh(
      new THREE.SphereGeometry(0.06, 16, 16),
      new THREE.MeshBasicMaterial({ color: COL_WHITE, transparent: true,
        blending: THREE.AdditiveBlending, depthWrite: false })
    );
    g.add(bead);
    g.userData = { ...d, bead };
    scene.add(g);
    rings.push(g);
  });

  // ---- Threat Intelligence Nodes ----
  const NODE_COUNT = 7;
  const nodes = [];
  const nodeGroup = new THREE.Group();
  scene.add(nodeGroup);
  for (let i = 0; i < NODE_COUNT; i++) {
    const u = Math.random(), v = Math.random();
    const th = 2 * Math.PI * u, ph = Math.acos(2 * v - 1);
    const r = 4.0 + Math.random() * 0.8;
    const pos = new THREE.Vector3(
      r * Math.sin(ph) * Math.cos(th),
      r * Math.cos(ph) * 0.7,
      r * Math.sin(ph) * Math.sin(th)
    );
    const node = new THREE.Mesh(
      new THREE.IcosahedronGeometry(0.13, 0),
      new THREE.MeshStandardMaterial({ color: COL_CYAN, emissive: COL_CYAN,
        emissiveIntensity: 1.1, metalness: 0.6, roughness: 0.3 })
    );
    node.position.copy(pos);
    nodeGroup.add(node);

    const lineGeo = new THREE.BufferGeometry().setFromPoints(
      [new THREE.Vector3(0,0,0), pos]);
    const line = new THREE.Line(lineGeo, new THREE.LineBasicMaterial({
      color: COL_BLUE, transparent: true, opacity: 0.12,
      blending: THREE.AdditiveBlending, depthWrite: false }));
    nodeGroup.add(line);

    const packet = new THREE.Mesh(
      new THREE.SphereGeometry(0.05, 12, 12),
      new THREE.MeshBasicMaterial({ color: COL_WHITE, transparent: true,
        blending: THREE.AdditiveBlending, depthWrite: false }));
    nodeGroup.add(packet);

    nodes.push({ mesh: node, line, packet, pos,
      phase: Math.random() * Math.PI * 2, speed: 0.15 + Math.random() * 0.2 });
  }

  // ---- Network Protection Shield ----
  const shield = new THREE.Group();
  scene.add(shield);
  const SHIELD_R = 5.4;
  const shieldSurface = new THREE.Mesh(
    new THREE.SphereGeometry(SHIELD_R, 64, 64),
    new THREE.MeshPhysicalMaterial({ color: COL_BLUE, metalness: 0, roughness: 0,
      transparent: true, opacity: 0.05, transmission: 0.6, side: THREE.DoubleSide,
      depthWrite: false })
  );
  shield.add(shieldSurface);
  const shieldWire = new THREE.LineSegments(
    new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(SHIELD_R, 3)),
    new THREE.LineBasicMaterial({ color: COL_CYAN, transparent: true,
      opacity: 0.12, blending: THREE.AdditiveBlending, depthWrite: false })
  );
  shield.add(shieldWire);

  const scan = new THREE.Mesh(
    new THREE.IcosahedronGeometry(1, 4),
    new THREE.MeshBasicMaterial({ color: COL_CYAN, wireframe: true,
      transparent: true, opacity: 0, blending: THREE.AdditiveBlending,
      depthWrite: false })
  );
  scene.add(scan);

  // ---- AI Detection Panels ----
  const PANEL_TITLES = [
    'Threat Detection', 'Network Monitoring', 'Endpoint Security',
    'Threat Intelligence', 'Incident Response',
  ];
  const panels = [];
  PANEL_TITLES.forEach((title, i) => {
    const c = document.createElement('canvas');
    c.width = 512; c.height = 320;
    const ctx = c.getContext('2d');
    const tex = new THREE.CanvasTexture(c);
    tex.colorSpace = THREE.SRGBColorSpace;
    const mat = new THREE.MeshBasicMaterial({ map: tex, transparent: true,
      opacity: 0.9, depthWrite: false, side: THREE.DoubleSide });
    const plane = new THREE.Mesh(new THREE.PlaneGeometry(2.3, 1.44), mat);
    const ang = (i / PANEL_TITLES.length) * Math.PI * 2;
    plane.position.set(Math.cos(ang) * 5.0, 2.6 + Math.sin(ang * 2) * 0.6,
                       Math.sin(ang) * 5.0);
    plane.userData = { title, ctx, tex, canvas: c, phase: i * 1.3, ang };
    scene.add(plane);
    panels.push(plane);
  });

  function drawPanel(p, t) {
    const { ctx, canvas, title, phase } = p.userData;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'rgba(8,18,38,0.55)';
    roundRect(ctx, 8, 8, canvas.width - 16, canvas.height - 16, 28); ctx.fill();
    ctx.strokeStyle = 'rgba(80,200,255,0.45)'; ctx.lineWidth = 2;
    roundRect(ctx, 8, 8, canvas.width - 16, canvas.height - 16, 28); ctx.stroke();
    ctx.fillStyle = '#eaf4ff';
    ctx.font = '600 34px -apple-system, "SF Pro Display", sans-serif';
    ctx.fillText(title, 34, 64);
    const bars = 5, bw = 26, gap = 14, x0 = 34, y0 = 110, maxH = 120;
    for (let i = 0; i < bars; i++) {
      const h = (0.35 + 0.55 * Math.abs(Math.sin(t * 1.4 + phase + i * 0.7))) * maxH;
      const grad = ctx.createLinearGradient(0, y0 + maxH - h, 0, y0 + maxH);
      grad.addColorStop(0, 'rgba(50,214,255,0.95)');
      grad.addColorStop(1, 'rgba(10,132,255,0.25)');
      ctx.fillStyle = grad;
      roundRect(ctx, x0 + i * (bw + gap), y0 + maxH - h, bw, h, 6); ctx.fill();
    }
    ctx.strokeStyle = 'rgba(180,230,255,0.7)'; ctx.lineWidth = 2;
    ctx.beginPath();
    for (let x = 0; x <= 200; x += 4) {
      const yy = 250 + Math.sin((x * 0.08) + t * 2 + phase) * 14
                     * (0.5 + 0.5 * Math.sin(t + x * 0.02));
      if (x === 0) ctx.moveTo(300 + x, yy); else ctx.lineTo(300 + x, yy);
    }
    ctx.stroke();
  }
  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  // ---- Ambient Particle Field ----
  const dust = (() => {
    const n = 1400, pos = new Float32Array(n * 3), col = new Float32Array(n * 3);
    const cA = new THREE.Color(COL_BLUE), cB = new THREE.Color(COL_CYAN);
    for (let i = 0; i < n; i++) {
      const r = 6 + Math.random() * 9;
      const th = Math.random() * Math.PI * 2, ph = Math.acos(2 * Math.random() - 1);
      pos[i*3]   = r * Math.sin(ph) * Math.cos(th);
      pos[i*3+1] = r * Math.cos(ph);
      pos[i*3+2] = r * Math.sin(ph) * Math.sin(th);
      const c = Math.random() < 0.5 ? cA : cB;
      col[i*3] = c.r; col[i*3+1] = c.g; col[i*3+2] = c.b;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    g.setAttribute('color', new THREE.BufferAttribute(col, 3));
    return new THREE.Points(g, new THREE.PointsMaterial({
      size: 0.04, vertexColors: true, transparent: true, opacity: 0.7,
      blending: THREE.AdditiveBlending, depthWrite: false }));
  })();
  scene.add(dust);

  // ---- Post-processing ----
  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new THREE.Vector2(W(), H()), 0.95, 0.55, 0.12);
  composer.addPass(bloom);
  composer.addPass(new OutputPass());

  // ---- Resize ----
  function resize() {
    const w = W(), h = H();
    renderer.setSize(w, h, false);
    composer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener('resize', resize);
  resize();

  // ---- Animate ----
  const clock = new THREE.Clock();
  let rafId = 0;
  function animate() {
    const t = clock.getElapsedTime();

    core.rotation.y = t * 0.25;
    core.rotation.x = Math.sin(t * 0.2) * 0.3;
    core.rotation.z = t * 0.12;
    core.position.y = Math.sin(t * 0.6) * 0.18;
    const pulse = 1 + Math.sin(t * 1.6) * 0.06;
    innerGlow.scale.setScalar(pulse);
    keyLight.intensity = 55 + Math.sin(t * 1.6) * 18;
    crystalMat.emissiveIntensity = 0.6 + Math.sin(t * 1.6) * 0.25;
    coreParticles.rotation.y = t * 0.4;
    coreParticles.rotation.x = t * 0.15;

    pulseRings.forEach((ring) => {
      const p = ((t * 0.4 + ring.userData.phase) % 1);
      ring.scale.setScalar(1 + p * 1.6);
      ring.material.opacity = Math.max(0, 0.5 * (1 - p));
    });

    rings.forEach((g) => {
      const { speed, axis, bead } = g.userData;
      g.rotation[axis] += speed * 0.01;
      const a = t * Math.abs(speed) * 3;
      bead.position.set(Math.cos(a) * g.userData.r, Math.sin(a) * g.userData.r, 0);
    });

    nodeGroup.rotation.y = t * 0.03;
    nodes.forEach((n) => {
      n.mesh.rotation.x += 0.01; n.mesh.rotation.y += 0.013;
      const tw = 0.7 + 0.3 * Math.sin(t * 2 + n.phase);
      n.mesh.material.emissiveIntensity = 0.8 + tw;
      n.mesh.scale.setScalar(1 + 0.12 * Math.sin(t * 2 + n.phase));
      n.line.material.opacity = 0.08 + 0.18 * Math.max(0, Math.sin(t * 0.8 + n.phase));
      const p = (t * n.speed + n.phase) % 1;
      n.packet.position.lerpVectors(new THREE.Vector3(0,0,0), n.pos, p);
      n.packet.material.opacity = Math.sin(p * Math.PI);
    });

    const breathe = 1 + Math.sin(t * 0.5) * 0.015;
    shield.scale.setScalar(breathe);
    shieldWire.rotation.y = t * 0.02;
    shieldWire.material.opacity = 0.1 + 0.06 * Math.abs(Math.sin(t * 0.7));

    const scanT = (t % 5) / 5;
    scan.scale.setScalar(1.3 + scanT * (SHIELD_R - 1.2));
    scan.material.opacity = Math.max(0, 0.35 * (1 - scanT));
    scan.rotation.y = t * 0.5;

    panels.forEach((p, i) => {
      p.lookAt(camera.position);
      p.position.y += Math.sin(t * 0.8 + p.userData.phase) * 0.0008;
      p.material.opacity = 0.55 + 0.4 * Math.sin(t * 0.5 + p.userData.phase);
      if (i % 2 === 0) drawPanel(p, t);
    });
    panels.forEach((p, i) => { if (i % 2 === 1) drawPanel(p, t); });

    dust.rotation.y = t * 0.01;
    dust.rotation.x = Math.sin(t * 0.05) * 0.05;

    const radius = 9.2 + Math.sin(t * 0.13) * 0.7;
    const theta = t * 0.07;
    const phi = Math.PI / 2 + Math.sin(t * 0.09) * 0.14;
    camera.position.set(
      radius * Math.sin(phi) * Math.cos(theta),
      radius * Math.cos(phi) * 0.55 + Math.sin(t * 0.17) * 0.5,
      radius * Math.sin(phi) * Math.sin(theta)
    );
    camera.lookAt(0, 0, 0);

    composer.render();
    rafId = requestAnimationFrame(animate);
  }
  panels.forEach((p) => drawPanel(p, 0));
  animate();

  return function cleanup() {
    cancelAnimationFrame(rafId);
    window.removeEventListener('resize', resize);
    renderer.dispose();
  };
}
