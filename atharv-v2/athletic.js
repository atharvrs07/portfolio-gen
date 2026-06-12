// ===== ATHLETIC SECTION =====

let athleticInited = false;

function initAthletic() {
  if (athleticInited) return;
  athleticInited = true;
  setupTabs();
}

function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      switchTab(tab);
    });
  });
}

function switchTab(tab) {
  // Update buttons
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });

  // Update content
  document.querySelectorAll('.tab-content').forEach(c => {
    c.classList.remove('active');
  });

  const target = document.getElementById('tab-' + tab);
  if (target) {
    target.classList.add('active');

    // Init tennis game when tennis tab is activated
    if (tab === 'tennis') {
      setTimeout(() => initTennis(), 100);
    }
  }
}
