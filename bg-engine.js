/**
 * CYBERNETIC HIGH-PERFORMANCE BACKGROUND PARTICLE GENERATOR
 * Uses native HTML5 hardware acceleration to animate float nodes without dragging frame rates
 */
document.addEventListener("DOMContentLoaded", () => {
    const canvas = document.getElementById('cyberParticleCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let particles = [];
    
    // Auto-scale coordinate bounds safely to fit target monitor aspect resolution
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Seed Particle Parameters (Minimalist, low-opacity glowing dust)
    const particleCount = 65;
    for (let i = 0; i < particleCount; i++) {
        particles.push({
            x: Math.random() * window.innerWidth,
            y: Math.random() * window.innerHeight,
            radius: Math.random() * 1.5 + 0.5, // Ultra low-profile dust points
            speedX: (Math.random() - 0.5) * 0.25, // Slow linear float velocity
            speedY: (Math.random() - 0.5) * 0.25,
            alpha: Math.random() * 0.4 + 0.1 // Kept subtle so text stays easily readable
        });
    }

    // Main Hardware Graphics Rendering Loop
    function renderPipelineLoop() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Loop across particle array coordinate sets
        particles.forEach(p => {
            // Reposition coordinates based on drift parameters
            p.x += p.speedX;
            p.y += p.speedY;

            // Aspect boundary wrap-around safety (If particle escapes, loop it around)
            if (p.x < 0) p.x = canvas.width;
            if (p.x > canvas.width) p.x = 0;
            if (p.y < 0) p.y = canvas.height;
            if (p.y > canvas.height) p.y = 0;

            // Render current node state onto the Canvas plane
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            // Emissive neon cyan hue configuration
            ctx.fillStyle = `rgba(0, 240, 255, ${p.alpha})`;
            ctx.shadowBlur = 6;
            ctx.shadowColor = "#00f0ff";
            ctx.fill();
        });

        // Reset shadow blurring state before executing next stack draw cycle
        ctx.shadowBlur = 0;
        requestAnimationFrame(renderPipelineLoop);
    }

    // Fire the rendering loops
    requestAnimationFrame(renderPipelineLoop);
});