// React wrapper for the Nightwatch Cyber Defense Command hero.
// Usage:
//   import Hero from './Hero.jsx';
//   <Hero height="70vh" />
// Requires three as a peer dependency: `npm i three`. The bundler resolves the
// `three` and `three/addons/...` specifiers used inside hero-scene.js.
import { useEffect, useRef } from 'react';
import { initHero } from './hero-scene.js';

export default function Hero({ height = '70vh', className } = {}) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    let cleanup;
    try {
      cleanup = initHero(canvas);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Nightwatch hero failed to initialize WebGL:', err);
    }
    return () => {
      if (typeof cleanup === 'function') cleanup();
    };
  }, []);

  return (
    <div
      className={className}
      style={{ position: 'relative', width: '100%', height, overflow: 'hidden' }}
    >
      <canvas
        ref={canvasRef}
        style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', display: 'block' }}
      />
    </div>
  );
}
