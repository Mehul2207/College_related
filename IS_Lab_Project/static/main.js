document.addEventListener("DOMContentLoaded", () => {
  console.log("main.js loaded");

  // Apply fade-in animation to body and main content
  const body = document.body;
  body.classList.add('fade-in');

  const containers = document.querySelectorAll('main, .landing-container, .learn-container, .form-container, .result-container, .cipher-section');
  containers.forEach((container, index) => {
    setTimeout(() => {
      container.classList.add('fade-in');
    }, index * 200); // Staggered animation for each container
  });

  // Handle step animations for result page
  const steps = document.querySelectorAll(".step");
  const startBtn = document.getElementById("start-btn");
  const showAllBtn = document.getElementById("show-all-btn");

  if (steps.length > 0) {
    console.log(`Found ${steps.length} steps`);
    let index = 0;
    let intervalId = null;

    const revealStep = () => {
      if (index < steps.length) {
        const step = steps[index];
        console.log(`Revealing step ${index}: ${step.innerHTML.substring(0, 50)}...`);
        step.classList.remove("hidden");
        step.classList.add("visible");
        const isMatrix = step.innerHTML.includes("<table");
        const delay = isMatrix ? 2000 : 1000;
        setTimeout(() => {
          index++;
          if (index >= steps.length) {
            clearInterval(intervalId);
            startBtn.disabled = false;
            console.log("Animation completed");
          }
        }, delay);
      }
    };

    if (startBtn) {
      startBtn.addEventListener("click", () => {
        console.log("Start button clicked");
        steps.forEach((step, i) => {
          step.classList.add("hidden");
          step.classList.remove("visible");
          console.log(`Reset step ${i}`);
        });
        index = 0;
        startBtn.disabled = true;
        intervalId = setInterval(revealStep, 100);
      });
    }

    if (showAllBtn) {
      showAllBtn.addEventListener("click", () => {
        console.log("Show all button clicked");
        clearInterval(intervalId);
        steps.forEach((step, i) => {
          step.classList.remove("hidden");
          step.classList.add("visible");
          console.log(`Showing step ${i}`);
        });
        startBtn.disabled = false;
      });
    }
  }
});