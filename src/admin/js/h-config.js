// ===== CONFIG =====
function cloneJson(v) { return JSON.parse(JSON.stringify(v || {})); }
function getPath(obj, path) { return path.split('.').reduce((acc, key) => acc == null ? undefined : acc[key], obj); }
function setPath(obj, path, value) {
    const parts = path.split('.');
    let cur = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        const key = parts[i];
        if (!cur[key] || typeof cur[key] !== 'object') cur[key] = {};
        cur = cur[key];
    }
    cur[parts[parts.length - 1]] = value;
}
function configFieldId(path) { return `config-field-${path.replace(/[^a-z0-9]+/gi, '-')}`; }
function configSectionId(title) { return `config-section-${String(title || '').replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`; }
async function copyToClipboard(text, label = 'Copied') {
    try {
        await navigator.clipboard.writeText(String(text ?? ''));
        showToast('ok', label);
    } catch (_) {
        showToast('err', 'Clipboard copy failed');
    }
}
function copyFromData(button, label = 'Copied') {
    return copyToClipboard(attrDec(button?.dataset?.copy ?? ''), label);
}
function showToast(tone, text) {
    const root = document.getElementById('toast-root');
    if (!root || !text) return;
    const item = document.createElement('div');
    item.className = `toast${tone ? ` ${tone}` : ''}`;
    item.textContent = text;
    root.appendChild(item);
    setTimeout(() => item.remove(), TOAST_TIMEOUT_MS);
}
function findConfigField(path) {
    for (const section of CONFIG_EDITOR_FIELDS) {
        const field = section.fields.find(f => f.path === path);
        if (field) return field;
    }
    return null;
}
function buildConfigDraft(cfg) {
    const draft = {};
    CONFIG_EDITOR_FIELDS.forEach(section => section.fields.forEach(field => {
        setPath(draft, field.path, getPath(cfg || {}, field.path));
    }));
    return draft;
}
function configDraftIsDirty() {
    if (!S.configDraft || !S.cachedConfig) return false;
    return CONFIG_EDITOR_FIELDS.some(section => section.fields.some(field => JSON.stringify(getPath(S.configDraft, field.path)) !== JSON.stringify(getPath(S.cachedConfig, field.path))));
}
function validateConfigField(field, value) {
    if (field.type === 'select') {
        return field.options.includes(String(value)) ? '' : `Allowed values: ${field.options.join(', ')}`;
    }
    if (field.type === 'boolean') {
        return typeof value === 'boolean' ? '' : 'Value must be true or false';
    }
    if (field.type === 'number') {
        if (value == null || value === '' || Number.isNaN(value)) return 'Numeric value is required';
        if (!Number.isFinite(Number(value))) return 'Numeric value is required';
        if (field.min != null && Number(value) < field.min) return `Minimum is ${field.min}`;
        if (field.max != null && Number(value) > field.max) return `Maximum is ${field.max}`;
        return '';
    }
    const text = String(value ?? '').trim();
    if (!field.allowEmpty && !text) return 'This field cannot be empty';
    if ((field.path.includes('timeout') || field.path.includes('interval')) && text && !DURATION_RE.test(text)) return 'Use a duration like 250ms, 5s, 1m or 1h';
    return '';
}
function collectConfigValidationErrors() {
    const errors = {};
    if (!S.configDraft) return errors;
    CONFIG_EDITOR_FIELDS.forEach(section => section.fields.forEach(field => {
        const error = validateConfigField(field, getPath(S.configDraft, field.path));
        if (error) errors[field.path] = error;
    }));
    return errors;
}
function listChangedConfigFields() {
    if (!S.configDraft || !S.cachedConfig) return [];
    const changes = [];
    CONFIG_EDITOR_FIELDS.forEach(section => section.fields.forEach(field => {
        const before = getPath(S.cachedConfig, field.path);
        const after = getPath(S.configDraft, field.path);
        if (JSON.stringify(before) === JSON.stringify(after)) return;
        changes.push({ path: field.path, label: field.label, before, after, section: section.title });
    }));
    return changes;
}
function listRuntimeVsStartupConfigFields() {
    if (!S.cachedConfig || !S.cachedConfigStartup) return [];
    const changes = [];
    CONFIG_EDITOR_FIELDS.forEach(section => section.fields.forEach(field => {
        const runtime = getPath(S.cachedConfig, field.path);
        const startup = getPath(S.cachedConfigStartup, field.path);
        if (JSON.stringify(runtime) === JSON.stringify(startup)) return;
        changes.push({ path: field.path, label: field.label, before: startup, after: runtime, section: section.title });
    }));
    return changes;
}
function focusConfigField(path) {
    S.configFocusPath = path;
    const field = findConfigField(path);
    if (field) {
        for (const section of CONFIG_EDITOR_FIELDS) {
            if (section.fields.some(f => f.path === path)) S.configCollapsedSections[configSectionId(section.title)] = false;
        }
    }
    navTo('config');
    setTimeout(() => {
        renderConfig(S.cachedConfig || {});
        const root = document.getElementById(configFieldId(path));
        if (!root) return;
        root.scrollIntoView({ behavior: 'smooth', block: 'center' });
        const input = root.querySelector('input, select');
        if (input) input.focus();
    }, 30);
}
function setConfigStatus(tone, text, notify = true) {
    S.configStatus = { tone: tone || '', text: text || '' };
    if (text && tone && notify) showToast(tone, text);
    const el = document.getElementById('config-status');
    if (!el) return;
    el.className = `config-status${tone ? ` ${tone}` : ''}`;
    el.textContent = text || '';
}
function toggleConfigSectionCollapse(sectionId) {
    S.configCollapsedSections[sectionId] = !S.configCollapsedSections[sectionId];
    renderConfig(S.cachedConfig || {});
}
function renderConfigSummary(cfg) {
    const root = document.getElementById('config-summary');
    if (!root) return;
    const draftChanges = listChangedConfigFields();
    const runtimeChanges = listRuntimeVsStartupConfigFields();
    const validationErrors = Object.keys(collectConfigValidationErrors()).length;
    const editableCount = CONFIG_EDITOR_FIELDS.reduce((n, section) => n + section.fields.length, 0);
    root.innerHTML = `
        <div class="summary-card"><div class="k">Editable fields</div><div class="v">${editableCount}</div><div class="subtle">Runtime-safe controls only</div></div>
        <div class="summary-card"><div class="k">Draft changes</div><div class="v">${draftChanges.length}</div><div class="subtle">Pending before apply</div></div>
        <div class="summary-card"><div class="k">Runtime drift</div><div class="v">${runtimeChanges.length}</div><div class="subtle">Fields differing from startup</div></div>
        <div class="summary-card"><div class="k">Validation issues</div><div class="v">${validationErrors}</div><div class="subtle">Must be zero to apply</div></div>`;
}
function renderConfigDiffDrawer() {
    const drawer = document.getElementById('config-diff-drawer');
    if (!drawer) return;
    const draftChanges = listChangedConfigFields();
    const runtimeChanges = listRuntimeVsStartupConfigFields();
    if (!draftChanges.length && !runtimeChanges.length) {
        drawer.innerHTML = '';
        return;
    }
    const renderItems = (items, actionLabel) => items.length ? `<div class="config-diff-list">${items.map(item => `
        <div class="config-diff-item">
            <div class="t">${esc(item.label)} <span style="color:var(--text-4);font-weight:500">· ${esc(item.section)}</span></div>
            <div class="s mono">${esc(item.path)}</div>
            <div class="s">${esc(String(item.before))} → ${esc(String(item.after))}</div>
            ${actionLabel ? `<div class="route-inline-meta" style="margin-top:0.45rem"><button class="config-mini-btn" data-action="focus-config-field" data-path="${attrEnc(item.path)}">${actionLabel}</button></div>` : ''}
        </div>`).join('')}</div>` : '<div class="empty">No differences</div>';
    drawer.innerHTML = `
        <div class="config-diff-drawer">
            <div class="panel-head"><div><div class="panel-title">Config diff drawer</div><div class="subtle">Draft deltas and live runtime drift versus startup snapshot</div></div></div>
            <div class="panel-body config-diff-grid">
                <div>
                    <div class="panel-title" style="margin-bottom:0.6rem">Draft changes</div>
                    ${renderItems(draftChanges, 'Focus field')}
                </div>
                <div>
                    <div class="panel-title" style="margin-bottom:0.6rem">Runtime vs startup</div>
                    ${renderItems(runtimeChanges, 'Inspect')}
                </div>
            </div>
        </div>`;
}
function renderConfigEditor(cfg) {
    if (!cfg || typeof cfg !== 'object') {
        document.getElementById('config-editor').innerHTML = '<div class="empty">No runtime configuration available</div>';
        return;
    }
    if (!S.configDraft) S.configDraft = buildConfigDraft(cfg);
    const dirty = configDraftIsDirty();
    const errors = collectConfigValidationErrors();
    const hasErrors = Object.keys(errors).length > 0;
    document.getElementById('config-apply-btn').disabled = !dirty || hasErrors;
    const query = S.configSearch.trim().toLowerCase();
    const html = `<div class="config-editor-grid">${CONFIG_EDITOR_FIELDS.map(section => {
        const sectionId = configSectionId(section.title);
        const matchCount = section.fields.filter(field => {
            const current = getPath(cfg, field.path);
            const startup = getPath(S.cachedConfigStartup || {}, field.path);
            return !query || `${section.title} ${field.label} ${field.path} ${current ?? ''} ${startup ?? ''}`.toLowerCase().includes(query);
        }).length;
        const forceOpenForQuery = !!query && matchCount > 0;
        const collapsed = !forceOpenForQuery && !!S.configCollapsedSections[sectionId] && !(S.configFocusPath && section.fields.some(field => field.path === S.configFocusPath));
        return `
        <div id="${sectionId}" class="config-section${matchCount && query ? ' match' : ''}${collapsed ? ' collapsed' : ''}">
            <div class="config-section-head"><div><div class="config-section-title">${esc(section.title)}</div><div class="config-section-sub">${esc(section.subtitle)}${query ? ` · ${matchCount} match` : ''}</div></div><button class="config-collapse-btn" data-action="toggle-config-section" data-section="${attrEnc(sectionId)}">${collapsed ? 'Expand' : 'Collapse'}</button></div>
            <div class="config-form">${section.fields.map(field => {
                const value = getPath(S.configDraft, field.path);
                const current = getPath(cfg, field.path);
                const startup = getPath(S.cachedConfigStartup || {}, field.path);
                const changed = JSON.stringify(value) !== JSON.stringify(current);
                const startupChanged = S.cachedConfigStartup && JSON.stringify(current) !== JSON.stringify(startup);
                const error = errors[field.path] || '';
                const fieldClass = `config-field${changed ? ' changed' : ''}${error ? ' invalid' : ''}${S.configFocusPath === field.path ? ' focused' : ''}`;
                let input = '';
                if (field.type === 'select') {
                    input = `<select class="config-select js-config-input" data-path="${attrEnc(field.path)}" data-type="select">${field.options.map(opt => `<option value="${esc(opt)}" ${String(value)===String(opt)?'selected':''}>${esc(opt)}</option>`).join('')}</select>`;
                } else if (field.type === 'boolean') {
                    input = `<select class="config-select js-config-input" data-path="${attrEnc(field.path)}" data-type="boolean"><option value="true" ${value===true?'selected':''}>true</option><option value="false" ${value===false?'selected':''}>false</option></select>`;
                } else {
                    input = `<input class="config-input js-config-input" data-path="${attrEnc(field.path)}" data-type="${esc(field.type)}" type="${field.type === 'number' ? 'number' : 'text'}" value="${esc(value ?? '')}" ${field.min != null ? `min="${field.min}"` : ''} ${field.max != null ? `max="${field.max}"` : ''} />`;
                }
                const notes = [field.hint || ''];
                if (startup !== undefined) notes.push(`startup: ${String(startup)}`);
                if (changed) notes.push('draft modified');
                if (startupChanged) notes.push('runtime differs from startup');
                if (error) notes.push(error);
                return `<div id="${configFieldId(field.path)}" class="${fieldClass}"><div class="config-field-head"><label>${esc(field.label)}</label><div class="config-field-tools"><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(String(current ?? ''))}" data-label="${attrEnc('Current value copied')}">Copy current</button>${startup !== undefined ? `<button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(String(startup ?? ''))}" data-label="${attrEnc('Startup value copied')}">Copy startup</button>` : ''}</div></div>${input}<small>${notes.map((note, idx) => idx === notes.length - 1 && error ? `<span class="config-note-error">${esc(note)}</span>` : esc(note)).join(' · ')}</small></div>`;
            }).join('')}</div>
        </div>`;
    }).join('')}</div>`;
    document.getElementById('config-editor').innerHTML = html;
    renderConfigSummary(cfg);
    renderConfigDiffDrawer();
    setConfigStatus(S.configStatus.tone, S.configStatus.text || (hasErrors ? 'Fix validation errors before applying runtime changes.' : dirty ? 'Draft has unapplied runtime changes.' : 'Only runtime-safe fields are editable here.'), false);
}
function updateConfigDraft(path, type, raw) {
    if (!S.configDraft) S.configDraft = buildConfigDraft(S.cachedConfig || {});
    let value = raw;
    if (type === 'number') value = raw === '' ? null : Number(raw);
    if (type === 'boolean') value = raw === 'true';
    setPath(S.configDraft, path, value);
    S.configFocusPath = path;
    renderConfig(S.cachedConfig || {});
}
function revertConfigDraft() {
    S.configDraft = buildConfigDraft(S.cachedConfig || {});
    setConfigStatus('warn', 'Draft reverted to the current live runtime config.');
    renderConfig(S.cachedConfig || {});
}
async function applyRuntimeConfig() {
    if (!S.cachedConfig || !S.configDraft || !configDraftIsDirty()) return;
    const errors = collectConfigValidationErrors();
    if (Object.keys(errors).length > 0) {
        setConfigStatus('err', 'Fix validation errors before applying runtime changes.');
        renderConfig(S.cachedConfig || {});
        return;
    }
    const changes = listChangedConfigFields();
    const preview = changes.slice(0, 8).map(change => `• ${change.label}: ${String(change.before)} → ${String(change.after)}`).join('\n');
    const more = changes.length > 8 ? `\n… +${changes.length - 8} more field(s)` : '';
    if (!confirm(`Apply ${changes.length} runtime config change(s)?\n\n${preview}${more}`)) {
        setConfigStatus('warn', 'Apply cancelled.');
        return;
    }
    setConfigStatus('', 'Applying runtime configuration…');
    try {
        const response = await fetch(API + '/config', {
            method: 'PUT',
            headers: { ...hdrs(), 'Content-Type': 'application/json' },
            body: JSON.stringify(S.configDraft)
        });
        const data = await response.json();
        if (!data.success) {
            setConfigStatus('err', data.error || 'Runtime config update failed.');
            return;
        }
        S.configDraft = null;
        setConfigStatus('ok', data.message || 'Runtime configuration updated.');
        await refreshStatic();
    } catch (_) {
        setConfigStatus('err', 'Runtime config update failed.');
    }
}
async function resetRuntimeConfigToStartup() {
    if (!confirm('Reset all live runtime-editable settings back to the startup snapshot?')) return;
    setConfigStatus('', 'Resetting runtime configuration to startup snapshot…');
    try {
        const response = await fetch(API + '/config/reset', { method: 'POST', headers: hdrs() });
        const data = await response.json();
        if (data.success === false) {
            setConfigStatus('err', data.error || 'Reset failed.');
            return;
        }
        S.configDraft = null;
        setConfigStatus('ok', data.message || 'Runtime configuration reset to startup snapshot.');
        await refreshStatic();
    } catch (_) {
        setConfigStatus('err', 'Reset failed.');
    }
}
window.addEventListener('beforeunload', e => {
    if (!configDraftIsDirty()) return;
    e.preventDefault();
    e.returnValue = '';
});
document.addEventListener('keydown', e => {
    const applyCombo = (e.ctrlKey || e.metaKey) && e.key === 'Enter';
    if (applyCombo && document.getElementById('page-config')?.classList.contains('active')) {
        if (!document.getElementById('config-apply-btn')?.disabled) {
            e.preventDefault();
            applyRuntimeConfig();
        }
    }
    if (e.key === 'Escape' && document.getElementById('page-config')?.classList.contains('active') && S.configFocusPath) {
        S.configFocusPath = '';
        renderConfig(S.cachedConfig || {});
    }
});
function filterConfig() { S.configSearch = document.getElementById('config-search').value || ''; renderConfig(S.cachedConfig || {}); }
function toggleConfigDiffs() {
    S.configDiffOnly = !S.configDiffOnly;
    document.getElementById('config-diff-btn').classList.toggle('on', S.configDiffOnly);
    renderConfig(S.cachedConfig || {});
}
function resetConfigFilters() {
    S.configSearch = ''; S.configDiffOnly = false;
    document.getElementById('config-search').value = '';
    document.getElementById('config-diff-btn').classList.remove('on');
    renderConfig(S.cachedConfig || {});
}
function renderConfig(cfg) {
    renderConfigEditor(cfg);
    if(!cfg||typeof cfg!=='object'){document.getElementById('config-meta').textContent='0 entries';document.getElementById('config-list').innerHTML='<div class="empty">No config loaded</div>';return;}
    const sens=['admin_token','token','password'];
    const baseline = S.cachedConfigStartup || {};
    const rows=[];
    (function walk(o,pfx){Object.keys(o).sort().forEach(k=>{
        if (k === 'meta') return;
        const fk=pfx?pfx+'.'+k:k, v=o[k];
        const isSens=sens.some(s=>k.toLowerCase().includes(s));
        if(Array.isArray(v)){
            if(!v.length){ rows.push({ fk, value: '[]', isSens, isDiff: JSON.stringify(v)!==JSON.stringify(getPath(baseline, fk)) }); return; }
            if(v.every(x=>x==null || typeof x!=='object')){ rows.push({ fk, value: JSON.stringify(v), isSens, isDiff: JSON.stringify(v)!==JSON.stringify(getPath(baseline, fk)) }); return; }
            v.forEach((item, idx) => walk(item, `${fk}[${idx}]`));
            return;
        }
        if(v&&typeof v==='object'){walk(v,fk);return;}
        const value = typeof v==='boolean'?(v?'true':'false'):String(v);
        rows.push({ fk, value, isSens, isDiff: JSON.stringify(v)!==JSON.stringify(getPath(baseline, fk)) });
    });})(cfg,'');
    const query = S.configSearch.trim().toLowerCase();
    const visible = rows.filter(row => {
        if (S.configDiffOnly && !row.isDiff) return false;
        if (!query) return true;
        return `${row.fk} ${row.value}`.toLowerCase().includes(query);
    });
    let h='<div class="config-pre">';
    visible.forEach(row => {
        const cls=row.isSens?'mask':row.isDiff?'diff':'';
        const disp=row.isSens?'••••••••':row.value;
        h+=`<span class="ck">${esc(row.fk)}</span>: <span class="cv ${cls}">${esc(disp)}</span>\n`;
    });
    h+='</div>';
    document.getElementById('config-meta').textContent = `${visible.length} shown · ${rows.length} entries`;
    document.getElementById('config-list').innerHTML=visible.length ? h : '<div class="empty">No config entries match the current filter</div>';
}


function exportConfig(){const data=cloneJson(S.cachedConfig||{});if(data&&typeof data==='object') delete data.meta;dl(data,'sentirum-config.json');}
