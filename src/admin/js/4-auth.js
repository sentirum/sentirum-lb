// ===== AUTH =====
async function doLogin() {
    const u=document.getElementById('username-input').value.trim(), p=document.getElementById('password-input').value;
    try { const r=await fetch(API+'/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})}); const d=await r.json(); if(d.success&&d.token){S.token=d.token;S.username=d.user||u;localStorage.setItem('admin_token',S.token);localStorage.setItem('admin_user',S.username);showApp();}else document.getElementById('login-error').style.display='block'; } catch(e){document.getElementById('login-error').style.display='block';}
}
async function doLogout() {
    try{await fetch(API+'/logout',{method:'POST',headers:hdrs()});}catch(e){}
    if (S.staticRefreshTimer) clearTimeout(S.staticRefreshTimer);
    if (S.metricsSse) S.metricsSse.close();
    stopLogStream();
    localStorage.removeItem('admin_token');localStorage.removeItem('admin_user');location.reload();
}
function showApp() {
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('app').classList.add('active');
    document.getElementById('user-name').textContent = S.username;
    document.getElementById('user-avatar').textContent = (S.username[0] || '?').toUpperCase();
    if (!S.charts.latency || !S.charts.status) initCharts();
    startMetrics();
    refreshStatic();
}

