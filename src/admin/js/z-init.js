// ===== INIT =====
renderTargetDetailEmpty();
syncTargetQuickFilters();
syncRouteQuickFilters();
if(S.token&&S.username){
    fetch(API+'/me',{headers:hdrs()}).then(r=>r.json()).then(d=>{if(d.authenticated)showApp();else{localStorage.removeItem('admin_token');localStorage.removeItem('admin_user');}}).catch(()=>{localStorage.removeItem('admin_token');localStorage.removeItem('admin_user');});
}
document.getElementById('password-input').addEventListener('keypress',e=>{if(e.key==='Enter')doLogin();});
