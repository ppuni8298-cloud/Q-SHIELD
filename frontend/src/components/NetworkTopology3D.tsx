import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import * as THREE from 'three';

export interface NodeItem {
  node_id: string;
  node_type?: string;
  status: string;
  health?: string;
  last_sync?: string;
  revocation_version?: number;
  ip_address?: string;
  security_domain?: string;
}

interface NetworkTopologyProps {
  nodes?: NodeItem[];
  onSelectNode?: (node: NodeItem) => void;
  selectedNodeId?: string | null;
}

export const NetworkTopology3D: React.FC<NetworkTopologyProps> = ({
  nodes = [],
  onSelectNode,
  selectedNodeId,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<NodeItem | null>(null);
  const [hoveredNode, setHoveredNode] = useState<NodeItem | null>(null);

  // Status to Color Mapper
  const getNodeColor = (status: string, health?: string) => {
    const s = (status || '').toLowerCase();
    const h = (health || '').toLowerCase();
    if (s === 'revoked' || s === 'blocked' || h === 'compromised') return 0xef4444; // Red
    if (s === 'pending' || s === 'revocation_pending') return 0xfb923c; // Orange
    if (s === 'warning' || s === 'degraded' || h === 'warning') return 0xf59e0b; // Amber
    if (s === 'offline' || s === 'disconnected') return 0x64748b; // Grey
    return 0x22c55e; // Green/Emerald
  };

  useEffect(() => {
    if (!mountRef.current) return;
    const container = mountRef.current;
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 500;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
    camera.position.set(0, 5, 11);
    camera.lookAt(0, 0, 0);

    let gl = null;
    try {
      const testCanvas = document.createElement('canvas');
      gl = testCanvas.getContext('webgl') || testCanvas.getContext('experimental-webgl');
    } catch {
      gl = null;
    }
    if (!gl) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' });
      renderer.setSize(width, height);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      container.appendChild(renderer.domElement);
    } catch {
      return;
    }

    // Lights
    scene.add(new THREE.AmbientLight(0x131e38, 2.0));
    const mainLight = new THREE.PointLight(0x00d9ff, 3.0, 30);
    mainLight.position.set(0, 2, 0);
    scene.add(mainLight);

    const group = new THREE.Group();
    scene.add(group);

    // 1. Central Core: Q-SHIELD Primary Control Plane
    const coreGeo = new THREE.SphereGeometry(1.1, 32, 32);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x00d9ff,
      emissive: 0x0055aa,
      emissiveIntensity: 0.9,
      roughness: 0.2,
      metalness: 0.8,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    group.add(coreMesh);

    // Core Wireframe Ring
    const ringGeo = new THREE.RingGeometry(1.6, 1.68, 64);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0x3578ff, side: THREE.DoubleSide, transparent: true, opacity: 0.6 });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    ringMesh.rotation.x = Math.PI / 2;
    group.add(ringMesh);

    // 2. Render Distributed Nodes
    // If no real nodes provided yet, create default fallback set
    const effectiveNodes: NodeItem[] = nodes.length > 0 ? nodes : [
      { node_id: 'control-plane-01', node_type: 'PRIMARY_CORE', status: 'healthy', health: 'healthy', last_sync: 'Just now', revocation_version: 14 },
      { node_id: 'edge-relay-east-1', node_type: 'EDGE_RELAY', status: 'healthy', health: 'healthy', last_sync: '12s ago', revocation_version: 14 },
      { node_id: 'edge-relay-west-1', node_type: 'EDGE_RELAY', status: 'healthy', health: 'healthy', last_sync: '8s ago', revocation_version: 14 },
      { node_id: 'gateway-dmz-01', node_type: 'SECURITY_GATEWAY', status: 'warning', health: 'degraded', last_sync: '45s ago', revocation_version: 13 },
      { node_id: 'gateway-dmz-02', node_type: 'SECURITY_GATEWAY', status: 'revocation_pending', health: 'warning', last_sync: '1m ago', revocation_version: 12 },
      { node_id: 'isolated-node-09', node_type: 'WORKER_NODE', status: 'revoked', health: 'compromised', last_sync: '14m ago', revocation_version: 10 },
      { node_id: 'backup-standby-01', node_type: 'STANDBY_REPLICA', status: 'offline', health: 'offline', last_sync: '1h ago', revocation_version: 11 },
    ];

    const nodeMeshes: { mesh: THREE.Mesh; nodeData: NodeItem }[] = [];
    const lineMat = new THREE.LineBasicMaterial({ color: 0x3578ff, transparent: true, opacity: 0.45 });

    const radius = 4.8;
    effectiveNodes.forEach((node, idx) => {
      const angle = (idx / effectiveNodes.length) * Math.PI * 2;
      const heightOffset = Math.sin(idx * 1.5) * 0.9;
      const nx = Math.cos(angle) * radius;
      const nz = Math.sin(angle) * radius;
      const ny = heightOffset;

      const nodeColor = getNodeColor(node.status, node.health);
      const nodeGeo = new THREE.SphereGeometry(0.38, 20, 20);
      const nodeMat = new THREE.MeshStandardMaterial({
        color: nodeColor,
        emissive: nodeColor,
        emissiveIntensity: 0.6,
        roughness: 0.3,
      });
      const nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
      nodeMesh.position.set(nx, ny, nz);
      group.add(nodeMesh);

      nodeMeshes.push({ mesh: nodeMesh, nodeData: node });

      // Connection Line to Central Core
      const points = [new THREE.Vector3(0, 0, 0), new THREE.Vector3(nx, ny, nz)];
      const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
      const line = new THREE.Line(lineGeo, lineMat);
      group.add(line);
    });

    // Raycasting for Click / Hover Selection
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2(-999, -999);

    const onPointerMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes.map(m => m.mesh));
      if (intersects.length > 0) {
        const found = nodeMeshes.find(m => m.mesh === intersects[0].object);
        if (found) {
          setHoveredNode(found.nodeData);
          container.style.cursor = 'pointer';
          return;
        }
      }
      setHoveredNode(null);
      container.style.cursor = 'default';
    };

    const onPointerClick = () => {
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(nodeMeshes.map(m => m.mesh));
      if (intersects.length > 0) {
        const found = nodeMeshes.find(m => m.mesh === intersects[0].object);
        if (found) {
          setSelectedNode(found.nodeData);
          if (onSelectNode) onSelectNode(found.nodeData);
        }
      }
    };

    container.addEventListener('mousemove', onPointerMove);
    container.addEventListener('click', onPointerClick);

    // Animation Loop
    let animationFrame: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrame = requestAnimationFrame(animate);
      const t = clock.getElapsedTime();

      group.rotation.y = t * 0.12;
      coreMesh.rotation.y = -t * 0.3;
      ringMesh.rotation.z = t * 0.2;

      // Pulse Central Light
      mainLight.intensity = 2.4 + Math.sin(t * 3) * 0.6;

      renderer.render(scene, camera);
    };
    animate();

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
      container.removeEventListener('mousemove', onPointerMove);
      container.removeEventListener('click', onPointerClick);
      window.removeEventListener('resize', onResize);
      renderer.dispose();
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [nodes]);

  // Sync external selected node
  useEffect(() => {
    if (selectedNodeId && nodes.length > 0) {
      const match = nodes.find(n => n.node_id === selectedNodeId);
      if (match) setSelectedNode(match);
    }
  }, [selectedNodeId, nodes]);

  const activeInspectNode = selectedNode || hoveredNode;

  return (
    <div className="relative w-full h-[400px] glass-panel rounded-xl overflow-hidden flex flex-col border border-slate-800">
      {/* Topology Header Controls */}
      <div className="absolute top-4 left-5 z-10 flex items-center gap-3">
        <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
        <h4 className="text-sm font-bold tracking-wider text-slate-100 uppercase font-mono m-0">
          3D Distributed Node Mesh
        </h4>
        <span className="cyber-badge badge-info text-[10px]">Interactive WebGL</span>
      </div>

      {/* 3D Canvas Mount Point */}
      <div ref={mountRef} className="w-full h-full" />

      {/* Node Legend */}
      <div className="absolute bottom-4 left-5 z-10 flex flex-wrap items-center gap-3 bg-slate-900/80 backdrop-blur-md px-3.5 py-2 rounded-xl border border-slate-800 text-[11px] font-mono">
        <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-500" /> Healthy</div>
        <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-500" /> Warning</div>
        <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-orange-400" /> Pending</div>
        <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-rose-500" /> Revoked</div>
        <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-slate-500" /> Offline</div>
      </div>

      {/* Selected Node Detailed Inspector Card */}
      {activeInspectNode && (
        <div className="absolute top-4 right-5 z-10 glass-panel-glow p-4 rounded-xl max-w-xs w-full shadow-2xl transition-all">
          <div className="flex items-center justify-between gap-2 border-b border-slate-700/60 pb-2 mb-2">
            <span className="text-xs font-mono font-bold text-cyan-400 truncate">{activeInspectNode.node_id}</span>
            <span className={`cyber-badge badge-${activeInspectNode.status} text-[10px]`}>
              {activeInspectNode.status}
            </span>
          </div>
          <div className="space-y-1.5 text-xs text-slate-300 font-mono">
            <div className="flex justify-between">
              <span className="text-slate-500">Role:</span>
              <span>{activeInspectNode.node_type || 'EDGE_NODE'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Revocation Seq:</span>
              <span className="text-cyan-300">v{activeInspectNode.revocation_version ?? 1}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Last Sync:</span>
              <span>{activeInspectNode.last_sync || 'Synchronized'}</span>
            </div>
            {activeInspectNode.ip_address && (
              <div className="flex justify-between">
                <span className="text-slate-500">IP:</span>
                <span>{activeInspectNode.ip_address}</span>
              </div>
            )}
            <Link
              to="/nodes"
              className="cyber-btn cyber-btn-primary w-full text-center text-[11px] py-1.5 mt-2.5 flex items-center justify-center gap-1 no-underline font-sans font-semibold tracking-wide"
            >
              Inspect in Node Monitor ➜
            </Link>
          </div>
        </div>
      )}
    </div>
  );
};
