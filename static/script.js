// ── Modals ────────────────────────────────────────────────────────────────────
function openShareModal(fileId, fileName) {
  document.getElementById('shareFileId').value = fileId;
  document.getElementById('shareFileName').textContent = fileName;
  document.getElementById('shareModal').classList.add('open');
}
function closeShareModal() {
  document.getElementById('shareModal').classList.remove('open');
}
function openQuotaModal(userId, username, currentMb) {
  document.getElementById('quotaUserId').value = userId;
  document.getElementById('quotaUsername').textContent = username;
  document.getElementById('newQuota').value = currentMb;
  document.getElementById('quotaModal').classList.add('open');
}
function closeQuotaModal() {
  document.getElementById('quotaModal').classList.remove('open');
}

// Fermer en cliquant à l'extérieur
document.addEventListener('click', e => {
  if (e.target.classList.contains('modal-overlay'))
    e.target.classList.remove('open');
});

// ── Upload zone ───────────────────────────────────────────────────────────────
const fileInput  = document.getElementById('fileInput');
const uploadZone = document.getElementById('uploadZone');
const uploadLabel = document.getElementById('uploadLabel');

if (fileInput && uploadZone) {
  // Clic sur la zone
  uploadZone.addEventListener('click', () => fileInput.click());

  // Sélection de fichier
  fileInput.addEventListener('change', function () {
    if (this.files.length > 0) {
      uploadLabel.innerHTML = '📄 <strong>' + this.files[0].name + '</strong>';
      uploadZone.style.borderColor = 'var(--cyan)';
      uploadZone.style.background = 'var(--cyan-glow2)';
    }
  });

  // Drag & drop
  uploadZone.addEventListener('dragover', e => {
    e.preventDefault();
    uploadZone.classList.add('drag-over');
  });
  uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('drag-over');
  });
  uploadZone.addEventListener('drop', e => {
    e.preventDefault();
    uploadZone.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      fileInput.files = files;
      uploadLabel.innerHTML = '📄 <strong>' + files[0].name + '</strong>';
      uploadZone.style.borderColor = 'var(--cyan)';
    }
  });
}

// ── Quota bar animation ───────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Anime la barre de quota au chargement
  const fills = document.querySelectorAll('.quota-bar-fill');
  fills.forEach(fill => {
    const pct = parseFloat(fill.dataset.percent) || 0;
    setTimeout(() => {
      fill.style.width = pct + '%';
      // Couleur selon le niveau
      if (pct >= 95) {
        fill.style.background = 'var(--red)';
        fill.style.boxShadow  = '0 0 8px var(--red-glow)';
      } else if (pct >= 80) {
        fill.style.background = 'linear-gradient(90deg, var(--orange), var(--red))';
      }
    }, 200);
  });

  // Stagger animation sur les file-rows
  document.querySelectorAll('.file-row').forEach((row, i) => {
    row.style.animationDelay = (i * 0.05) + 's';
  });

  // Stagger sur les stat-cards
  document.querySelectorAll('.stat-card').forEach((card, i) => {
    card.style.animationDelay = (i * 0.06 + 0.1) + 's';
  });

  // Auto-dismiss flash messages après 4s
  document.querySelectorAll('.flash').forEach(flash => {
    setTimeout(() => {
      flash.style.transition = 'opacity .4s ease, transform .4s ease';
      flash.style.opacity    = '0';
      flash.style.transform  = 'translateY(-8px)';
      setTimeout(() => flash.remove(), 400);
    }, 4000);
  });
});

// ── Confirm suppression avec style ───────────────────────────────────────────
document.querySelectorAll('form[onsubmit]').forEach(form => {
  // Le confirm natif est géré via onsubmit inline
});

// User menu dropdown
function toggleUserMenu() {
  const dropdown = document.getElementById('userDropdown');
  const userInfo = document.querySelector('.user-info');
  if (dropdown && userInfo) {
    dropdown.classList.toggle('show');
    userInfo.classList.toggle('active');
  }
}

// Fermer le menu en cliquant ailleurs
document.addEventListener('click', function(event) {
  const userMenu = document.querySelector('.user-menu');
  if (userMenu && !userMenu.contains(event.target)) {
    const dropdown = document.getElementById('userDropdown');
    const userInfo = document.querySelector('.user-info');
    if (dropdown) dropdown.classList.remove('show');
    if (userInfo) userInfo.classList.remove('active');
  }
});