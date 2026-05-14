// ===== EXPORT =====
// JSON download helpers — pure utility, no state dependencies.

function dl(d,f){const b=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=f;a.click();}
