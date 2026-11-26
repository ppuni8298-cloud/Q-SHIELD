import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';

const SECURITY_NODES = [
  { id: 'ident', label: 'IDENTITY VERIFIED', desc: 'Hardware-bound mTLS & post-quantum identity certificates', angle: 0, status: 'Verified' },
  { id: 'mlkem', label: 'ML-KEM-768', desc: 'NIST FIPS 203 post-quantum lattice key encapsulation', angle: Math.PI / 3, status: 'PQ-Active' },
  { id: 'zero', label: 'ZERO-TRUST ACCESS', desc: 'Continuous ABAC policy re-evaluation with sliding context', angle: (2 * Math.PI) / 3, status: 'Enforced' },
  { id: 'rot', label: 'KEY ROTATION', desc: 'Journal-backed synchronized cutoff with zero-downtime rollover', angle: Math.PI, status: 'Synced' },
  { id: 'rev', label: 'REVOCATION ACTIVE', desc: 'Sub-second event propagation across edge relays', angle: (4 * Math.PI) / 3, status: 'Live' },
  { id: 'aud', label: 'AUDIT VERIFIED', desc: 'SHA-256 hash-chained immutable ledger with HMAC proofs', angle: (5 * Math.PI) / 3, status: 'Immutable' },
];

export const QuantumShield3D: React.FC = () => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [activeNode, setActiveNode] = useState<typeof SECURITY_NODES[0] | null>(null);
  const [webGlSupported, setWebGlSupported] = useState(true);

  useEffect(() => {
    if (!mountRef.current) return;

    // Check WebGL availability safely for jsdom and headless test environments
    let gl = null;
    try {
      const canvas = document.createElement('canvas');
      gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    } catch {
      gl = null;
    }
    if (!gl) {
      setWebGlSupported(false);
      return;
    }

    const container = mountRef.current;
    const width = container.clientWidth || 600;
    const height = container.clientHeight || 600;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 8.5;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' });
      renderer.setSize(width, height);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      container.appendChild(renderer.domElement);
    } catch {
      setWebGlSupported(false);
      return;
    }

    // Lights
    const ambientLight = new THREE.AmbientLight(0x0d1e3d, 1.8);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0x00d9ff, 3.5, 20);
    pointLight.position.set(0, 0, 0);
    scene.add(pointLight);

    const blueLight = new THREE.DirectionalLight(0x3578ff, 2.5);
    blueLight.position.set(5, 5, 5);
    scene.add(blueLight);

    const violetLight = new THREE.DirectionalLight(0x8b5cf6, 2.0);
    violetLight.position.set(-5, -5, -2);
    scene.add(violetLight);

    // Group for entire shield system
    const systemGroup = new THREE.Group();
    scene.add(systemGroup);

    // 1. Central Quantum Core (Glowing Sphere + Wireframe)
    const coreGeo = new THREE.SphereGeometry(0.75, 24, 24);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x00d9ff,
      emissive: 0x0088cc,
      emissiveIntensity: 0.8,
      roughness: 0.2,
      metalness: 0.9,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    systemGroup.add(coreMesh);

    // Core Wireframe Glow
    const coreWireGeo = new THREE.IcosahedronGeometry(0.95, 1);
    const coreWireMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      wireframe: true,
      transparent: true,
      opacity: 0.45,
    });
    const coreWireMesh = new THREE.Mesh(coreWireGeo, coreWireMat);
    systemGroup.add(coreWireMesh);

    // 2. Quantum Shield Layers (Transparent Polyhedral Shells)
    const shieldGeo = new THREE.IcosahedronGeometry(2.1, 2);
    const shieldMat = new THREE.MeshPhysicalMaterial({
      color: 0x0055ff,
      metalness: 0.2,
      roughness: 0.1,
      transmission: 0.85,
      transparent: true,
      opacity: 0.45,
      reflectivity: 0.9,
      clearcoat: 1.0,
      wireframe: false,
    });
    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    systemGroup.add(shieldMesh);

    // Outer Facet Wireframe
    const shieldWireGeo = new THREE.IcosahedronGeometry(2.15, 2);
    const shieldWireMat = new THREE.MeshBasicMaterial({
      color: 0x00d9ff,
      wireframe: true,
      transparent: true,
      opacity: 0.35,
    });
    const shieldWireMesh = new THREE.Mesh(shieldWireGeo, shieldWireMat);
    systemGroup.add(shieldWireMesh);

    // 3. Orbiting Cryptographic Rings
    const ring1Geo = new THREE.TorusGeometry(3.0, 0.025, 16, 100);
    const ring1Mat = new THREE.MeshBasicMaterial({ color: 0x00d9ff, transparent: true, opacity: 0.7 });
    const ring1 = new THREE.Mesh(ring1Geo, ring1Mat);
    ring1.rotation.x = Math.PI / 3;
    systemGroup.add(ring1);

    const ring2Geo = new THREE.TorusGeometry(3.4, 0.025, 16, 100);
    const ring2Mat = new THREE.MeshBasicMaterial({ color: 0x8b5cf6, transparent: true, opacity: 0.65 });
    const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
    ring2.rotation.y = Math.PI / 4;
    ring2.rotation.x = -Math.PI / 6;
    systemGroup.add(ring2);

    const ring3Geo = new THREE.TorusGeometry(3.7, 0.02, 16, 100);
    const ring3Mat = new THREE.MeshBasicMaterial({ color: 0x3578ff, transparent: true, opacity: 0.5 });
    const ring3 = new THREE.Mesh(ring3Geo, ring3Mat);
    ring3.rotation.z = Math.PI / 5;
    ring3.rotation.x = Math.PI / 2.5;
    systemGroup.add(ring3);

    // 4. Data Particles Travelling along perimeter
    const particleCount = 120;
    const particleGeo = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
      const theta = (i / particleCount) * Math.PI * 2;
      const radius = 2.8 + Math.random() * 1.0;
      positions[i * 3] = Math.cos(theta) * radius;
      positions[i * 3 + 1] = Math.sin(theta) * radius;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 1.5;

      colors[i * 3] = 0.0;
      colors[i * 3 + 1] = 0.85 + Math.random() * 0.15;
      colors[i * 3 + 2] = 1.0;
    }
    particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    particleGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const particleMat = new THREE.PointsMaterial({
      size: 0.065,
      vertexColors: true,
      transparent: true,
      opacity: 0.85,
      blending: THREE.AdditiveBlending,
    });
    const particles = new THREE.Points(particleGeo, particleMat);
    systemGroup.add(particles);

    // Mouse Parallax
    let targetRotationX = 0;
    let targetRotationY = 0;
    const onMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top) / rect.height - 0.5;
      targetRotationY = x * 0.8;
      targetRotationX = y * 0.8;
    };
    window.addEventListener('mousemove', onMouseMove);

    // Animation Loop
    let animationFrame: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrame = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Slow smooth rotation
      shieldMesh.rotation.y = elapsedTime * 0.2;
      shieldMesh.rotation.x = Math.sin(elapsedTime * 0.15) * 0.1;
      shieldWireMesh.rotation.y = -elapsedTime * 0.25;

      coreMesh.rotation.y = -elapsedTime * 0.4;
      coreWireMesh.rotation.y = elapsedTime * 0.5;

      ring1.rotation.z = elapsedTime * 0.35;
      ring2.rotation.z = -elapsedTime * 0.28;
      ring3.rotation.z = elapsedTime * 0.22;

      particles.rotation.z = -elapsedTime * 0.15;

      // Pulse core light
      pointLight.intensity = 3.0 + Math.sin(elapsedTime * 3) * 0.8;

      // Smooth parallax interpolation
      systemGroup.rotation.y += (targetRotationY - systemGroup.rotation.y) * 0.05;
      systemGroup.rotation.x += (targetRotationX - systemGroup.rotation.x) * 0.05;

      renderer.render(scene, camera);
    };
    animate();

    // Resize Handler
    const onResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', onResize);

    return () => {
      cancelAnimationFrame(animationFrame);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('resize', onResize);
      renderer.dispose();
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, []);

  return (
    <div className="relative w-full h-[540px] md:h-[620px] flex items-center justify-center select-none">
      {/* 3D Canvas Mounting Container */}
      <div ref={mountRef} className="w-full h-full absolute inset-0 cursor-grab active:cursor-grabbing" />

      {/* Graceful Fallback if WebGL unavailable */}
      {!webGlSupported && (
        <div className="absolute inset-0 flex flex-col items-center justify-center p-8 text-center bg-gradient-to-br from-blue-950/40 to-slate-900/60 rounded-3xl border border-cyan-500/20">
          <div className="w-48 h-48 rounded-full border-2 border-cyan-400/40 flex items-center justify-center animate-pulse-glow mb-4">
            <div className="w-32 h-32 rounded-full border border-violet-400/50 flex items-center justify-center">
              <span className="text-3xl font-extrabold gradient-text-cyan">Q</span>
            </div>
          </div>
          <h4 className="text-lg font-bold text-slate-200">Quantum Security Engine Active</h4>
          <p className="text-xs text-slate-400 max-w-sm mt-1">Post-quantum cryptography & distributed zero-trust operational</p>
        </div>
      )}

      {/* Orbiting Security Status Floating Chips */}
      <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
        {SECURITY_NODES.map((node, i) => {
          // Calculate circle coordinate in percentage
          const radiusPercent = 42;
          const x = 50 + radiusPercent * Math.cos(node.angle);
          const y = 50 + radiusPercent * Math.sin(node.angle);

          return (
            <div
              key={node.id}
              className="absolute pointer-events-auto transform -translate-x-1/2 -translate-y-1/2 transition-all duration-300 hover:scale-110"
              style={{ left: `${x}%`, top: `${y}%` }}
              onMouseEnter={() => setActiveNode(node)}
              onMouseLeave={() => setActiveNode(null)}
            >
              <div className="glass-panel px-3 py-1.5 rounded-full flex items-center gap-2 cursor-pointer shadow-lg hover:border-cyan-400 bg-slate-900/80 backdrop-blur-md">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                <span className="text-[11px] font-bold tracking-wider text-slate-200 uppercase font-mono">{node.label}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Active Node Detail Card Overlay */}
      {activeNode && (
        <div className="absolute bottom-4 left-1/2 -translate-x-1/2 glass-panel-glow px-5 py-3 rounded-xl max-w-md w-[90%] z-20 pointer-events-none transition-all duration-200">
          <div className="flex items-center justify-between gap-3 mb-1">
            <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">{activeNode.label}</span>
            <span className="cyber-badge badge-ok text-[10px]">{activeNode.status}</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed m-0">{activeNode.desc}</p>
        </div>
      )}
    </div>
  );
};
