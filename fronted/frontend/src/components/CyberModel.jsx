import React, { useState } from 'react';
import { Canvas } from '@react-three/fiber';
import { useGLTF, Stage, OrbitControls, useProgress, Html, Environment } from '@react-three/drei';

function Loader() {
  const { progress } = useProgress();
  return (
    <Html center>
      <div className="text-[#00ff41] font-mono bg-black border border-[#00ff41] p-2 text-sm whitespace-nowrap shadow-[0_0_10px_#00ff41]">
        [ LOADING HOLOGRAM: {progress.toFixed(0)}% ]
      </div>
    </Html>
  );
}

function Model(props) {
  const { scene } = useGLTF('/cyber.glb');
  return <primitive object={scene} {...props} />;
}

export default function CyberScene() {
  const [isActive, setIsActive] = useState(false);

  return (
    <div 
      style={{ height: '100%', width: '100%', minHeight: '500px', position: 'relative', background: 'transparent', transition: 'all 0.3s' }}
      onMouseEnter={() => setIsActive(true)}
      onMouseLeave={() => setIsActive(false)}
    >
      
      <Canvas shadows dpr={[1, 2]} camera={{ fov: 45 }}>
        
        <React.Suspense fallback={<Loader />}>
          
          {/* --- 1. GLOBAL STUDIO LIGHTING (The "City" preset is very bright) --- */}
          <Environment preset="city" />

          {/* --- 2. STAGE LIGHTING BOOST --- */}
          <Stage 
            environment={null} 
            intensity={isActive ? 4 : 2} // <--- Much higher numbers here (was 0.5)
            contactShadow={false} 
            adjustCamera={1.5} 
            preset="rembrandt"
          >
            <Model /> 
          </Stage>

          {/* --- 3. NEON HIGHLIGHTS (Super Bright) --- */}
          {/* Base brightness */}
          <ambientLight intensity={2.0} color="#ffffff" /> 
          
          {/* Green Spotlight */}
          <pointLight position={[10, 10, 10]} color="#00ff41" intensity={20} distance={50} />
          
          {/* Red Rim Light */}
          <pointLight position={[-10, -5, -10]} color="#ff3333" intensity={10} distance={50} />
          
        </React.Suspense>
        
        <OrbitControls 
          autoRotate={isActive}
          autoRotateSpeed={2.0}
          enableZoom={isActive}
          enablePan={false}
          enableKeys={false}
          makeDefault
        />

      </Canvas>

      {!isActive && (
        <div style={{
          position: 'absolute', bottom: '20px', left: '50%', transform: 'translateX(-50%)',
          color: '#00ff41', fontSize: '10px', fontFamily: 'monospace',
          opacity: 0.9, pointerEvents: 'none', textShadow: '0 0 5px #00ff41'
        }}>
          [ HOVER TO ACTIVATE ]
        </div>
      )}

    </div>
  );
}