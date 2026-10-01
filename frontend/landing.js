// Three.js Neural Core 3D Landing Page
let scene, camera, renderer, particles;
let mouseX = 0;
let mouseY = 0;
let windowHalfX = window.innerWidth / 2;
let windowHalfY = window.innerHeight / 2;

function init3DLanding() {
    const container = document.getElementById('landing-3d-container');
    if (!container) return;

    // Scene
    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x050510, 0.002);

    // Camera
    camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 1, 2000);
    camera.position.z = 800;

    // Geometry
    const geometry = new THREE.BufferGeometry();
    const particlesCount = 2500;
    const posArray = new Float32Array(particlesCount * 3);
    const colorsArray = new Float32Array(particlesCount * 3);

    const color1 = new THREE.Color(0x7c3aed); // Purple
    const color2 = new THREE.Color(0x38bdf8); // Cyan
    const color3 = new THREE.Color(0xf43f5e); // Rose

    for(let i = 0; i < particlesCount * 3; i+=3) {
        // Spherical distribution
        const r = 400 + Math.random() * 100;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos((Math.random() * 2) - 1);
        
        posArray[i] = r * Math.sin(phi) * Math.cos(theta);
        posArray[i+1] = r * Math.sin(phi) * Math.sin(theta);
        posArray[i+2] = r * Math.cos(phi);

        // Random colors mix
        const mix = Math.random();
        let c;
        if(mix < 0.4) c = color1;
        else if(mix < 0.8) c = color2;
        else c = color3;

        colorsArray[i] = c.r;
        colorsArray[i+1] = c.g;
        colorsArray[i+2] = c.b;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colorsArray, 3));

    // Material
    const material = new THREE.PointsMaterial({
        size: 3,
        vertexColors: true,
        transparent: true,
        opacity: 0.8,
        blending: THREE.AdditiveBlending
    });

    // Mesh
    particles = new THREE.Points(geometry, material);
    scene.add(particles);

    // Renderer
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(window.innerWidth, window.innerHeight);
    container.appendChild(renderer.domElement);

    // Events
    document.addEventListener('mousemove', onDocumentMouseMove);
    window.addEventListener('resize', onWindowResize);
    
    // Setup Entry Button
    const entryBtn = document.getElementById('enter-core-btn');
    if (entryBtn) {
        entryBtn.addEventListener('click', enterDashboard);
    }

    animate();
}

function onWindowResize() {
    windowHalfX = window.innerWidth / 2;
    windowHalfY = window.innerHeight / 2;
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
}

function onDocumentMouseMove(event) {
    mouseX = event.clientX - windowHalfX;
    mouseY = event.clientY - windowHalfY;
}

function animate() {
    requestAnimationFrame(animate);
    render();
}

function render() {
    // Smooth camera movement based on mouse
    camera.position.x += (mouseX - camera.position.x) * 0.05;
    camera.position.y += (-mouseY - camera.position.y) * 0.05;
    camera.lookAt(scene.position);

    // Rotate particles
    particles.rotation.x += 0.001;
    particles.rotation.y += 0.002;

    renderer.render(scene, camera);
}

function enterDashboard() {
    const landingOverlay = document.getElementById('landing-overlay');
    const mainContent = document.getElementById('mainContent');
    const sidebar = document.getElementById('sidebar');

    if (landingOverlay) {
        // Zoom camera in rapidly
        gsap.to(camera.position, {
            z: -200,
            duration: 1.5,
            ease: "power2.in"
        });
        
        gsap.to(landingOverlay, {
            opacity: 0,
            duration: 1.2,
            delay: 0.5,
            onComplete: () => {
                landingOverlay.style.display = 'none';
                document.body.style.overflow = ''; // Restore scrolling if needed
            }
        });
        
        // Show main elements
        gsap.fromTo(mainContent, 
            { opacity: 0, y: 50 }, 
            { opacity: 1, y: 0, duration: 1, delay: 1, ease: "power2.out" }
        );
        gsap.fromTo(sidebar, 
            { opacity: 0, x: -50 }, 
            { opacity: 1, x: 0, duration: 1, delay: 1, ease: "power2.out" }
        );
    }
}

// Initialize on load
window.addEventListener('load', () => {
    // Hide main content initially
    document.getElementById('mainContent').style.opacity = '0';
    document.getElementById('sidebar').style.opacity = '0';
    document.body.style.overflow = 'hidden'; // Prevent scrolling on landing
    init3DLanding();
});
