const API_URL = 'http://localhost:3001/api';
let currentUser = null;

function getToken() { return localStorage.getItem('token'); }
function getUser() { return JSON.parse(localStorage.getItem('user') || '{}'); }

async function checkAuth() {
    if (!getToken()) { window.location.href = 'login.html'; return false; }
    const user = getUser();
    currentUser = user;
    document.getElementById('userName').innerText = user.displayName || user.email;
    document.getElementById('userAvatar').innerText = (user.displayName || user.email)[0].toUpperCase();
    document.getElementById('userRoleText').innerText = user.role;
    document.getElementById('userRole').innerHTML = user.role === 'super_admin' ? '🔑 سوبر أدمن' : (user.role === 'admin' ? '📋 أدمن' : '💻 مطور');
    return true;
}

function logout() { localStorage.clear(); window.location.href = 'login.html'; }
function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }

async function loadPage(page) {
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    document.querySelector(`[data-page="${page}"]`).classList.add('active');
    
    const titles = {
        dashboard: 'لوحة التحكم', clients: 'العملاء', projects: 'المشاريع', websites: 'المواقع المنشورة',
        builder: 'محرر الكود', media: 'مكتبة الوسائط', deploy: 'مركز النشر', domains: 'الدومينات',
        cloudflare: 'Cloudflare', r2: 'R2 Storage', backups: 'النسخ الاحتياطي', templates: 'القوالب',
        team: 'الفريق', chat: 'الدردشة', activity: 'سجل النشاطات', settings: 'الإعدادات'
    };
    document.getElementById('pageTitle').innerText = titles[page] || page;
    
    const contentDiv = document.getElementById('pageContent');
    try {
        const response = await fetch(`${page}.html`);
        if (response.ok) {
            const html = await response.text();
            contentDiv.innerHTML = html;
            if (page === 'dashboard') loadDashboardStats();
            if (page === 'clients' && window.loadClients) window.loadClients();
            if (page === 'projects' && window.loadProjects) window.loadProjects();
        } else { contentDiv.innerHTML = '<div class="card"><p>جاري تحميل الصفحة...</p></div>'; }
    } catch(e) { contentDiv.innerHTML = '<div class="card"><p>خطأ في تحميل الصفحة</p></div>'; }
}

async function loadDashboardStats() {
    try {
        const stats = await window.api.getStats();
        if (stats.success) {
            document.getElementById('statsGrid').innerHTML = `
                <div class="stat-card" onclick="loadPage('clients')"><div class="stat-value">${stats.stats.totalClients || 0}</div><div class="stat-label">العملاء</div></div>
                <div class="stat-card" onclick="loadPage('projects')"><div class="stat-value">${stats.stats.totalProjects || 0}</div><div class="stat-label">المشاريع</div></div>
                <div class="stat-card" onclick="loadPage('websites')"><div class="stat-value">${stats.stats.totalWebsites || 0}</div><div class="stat-label">المواقع المنشورة</div></div>
            `;
        }
    } catch(e) { console.error(e); }
}

checkAuth();