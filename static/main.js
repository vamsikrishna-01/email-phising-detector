document.addEventListener('DOMContentLoaded', () => {
// DOM Elements
const emailForm = document.getElementById('emailForm');
const clearBtn = document.getElementById('clearBtn');
const checkBtn = document.getElementById('checkBtn');
const loader = document.getElementById('loader');
const resultsSection = document.getElementById('results');

// Character counters for subject and body
document.getElementById('subject').addEventListener('input', function() {
    const count = this.value.length;
    document.getElementById('subject-count').textContent = count;
      if (loader) loader.classList.remove('hidden');
      if (checkBtn) checkBtn.setAttribute('disabled', 'true');
      if (clearBtn) clearBtn.setAttribute('disabled', 'true');
    });
  }

  // Visualize result with risk bar, confetti, and shake.
  if (resultCard && riskFill) {
    const status = resultCard.getAttribute('data-status'); // 'phishing' | 'safe'
    const risk = Number(resultCard.getAttribute('data-risk') || 0); // 0-100

    // Animate the bar after a tiny delay to allow CSS transitions
    requestAnimationFrame(() => {
      setTimeout(() => {
        riskFill.style.width = Math.max(0, Math.min(100, risk)) + '%';
      }, 50);
    });

    // Shake for phishing, confetti for safe
    if (status === 'phishing') {
      resultCard.classList.add('shake');
      setTimeout(() => resultCard.classList.remove('shake'), 900);
    } else {
      launchConfetti(24);
    }

    // Nice reactive glow following mouse over the card
    resultCard.addEventListener('mousemove', (e) => {
      const rect = resultCard.getBoundingClientRect();
      const xPercent = ((e.clientX - rect.left) / rect.width) * 100;
      resultCard.style.setProperty('--mx', xPercent + '%');
      resultCard.style.setProperty('--mx2', (100 - xPercent) + '%');
    });
  }

  function launchConfetti(count) {
    const colors = ['#7c4dff', '#03a9f4', '#00c853', '#ff9100', '#f50057', '#ffd54f', '#4db6ac'];
    const pieces = [];
    for (let i = 0; i < count; i++) {
      const el = document.createElement('div');
      el.className = 'confetti';
      el.style.left = Math.random() * 100 + 'vw';
      el.style.backgroundColor = colors[Math.floor(Math.random() * colors.length)];
      el.style.transform = `translateY(-20px) rotate(${Math.random() * 360}deg)`;
      el.style.transition = `transform ${1200 + Math.random() * 1200}ms cubic-bezier(.23,1,.32,1), opacity 300ms ease`;
      document.body.appendChild(el);
      pieces.push(el);
      // trigger fall
      requestAnimationFrame(() => {
        const translateY = window.innerHeight + 40 + Math.random() * 120;
        const rotate = 360 + Math.random() * 360;
        el.style.transform = `translateY(${translateY}px) rotate(${rotate}deg)`;
        el.style.opacity = '1';
      });
    }
    // cleanup
    setTimeout(() => pieces.forEach(p => p.remove()), 2600);
  }
});
