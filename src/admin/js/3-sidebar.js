// ===== MOBILE SIDEBAR =====
function toggleSidebar() { S.sidebarOpen=!S.sidebarOpen; document.getElementById('sidebar').classList.toggle('open',S.sidebarOpen); document.getElementById('sidebar-overlay').classList.toggle('active',S.sidebarOpen); }
function closeSidebar() { S.sidebarOpen=false; document.getElementById('sidebar').classList.remove('open'); document.getElementById('sidebar-overlay').classList.remove('active'); }

