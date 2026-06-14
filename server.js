// backend/server.js - النسخة النهائية المصححة 100%
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import admin from 'firebase-admin';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import multer from 'multer';
import { S3Client, PutObjectCommand, DeleteObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// ✅ حل مشكلة X-Forwarded-For (Rate Limit)
app.set('trust proxy', 1);

console.log('🚀 Starting VERO Backend...');
console.log(`📡 PORT: ${PORT}`);

// ========== MIDDLEWARE ==========
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(cookieParser());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, message: { success: false, error: 'Too many requests' } });
app.use('/api/', limiter);

// ========== FIREBASE ADMIN ==========
if (!process.env.FIREBASE_PROJECT_ID || !process.env.FIREBASE_PRIVATE_KEY || !process.env.FIREBASE_CLIENT_EMAIL) {
    console.error('❌ Firebase environment variables are missing');
    process.exit(1);
}

let privateKey = process.env.FIREBASE_PRIVATE_KEY;
if (privateKey.includes('\\n')) {
    privateKey = privateKey.replace(/\\n/g, '\n');
}
if (privateKey.startsWith('"') && privateKey.endsWith('"')) {
    privateKey = privateKey.slice(1, -1);
}

admin.initializeApp({
    credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: privateKey,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL
    }),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET
});

console.log('✅ Firebase initialized successfully');

const db = admin.firestore();
const auth = admin.auth();
const rtdb = admin.database();

console.log('✅ Firebase Realtime Database initialized');

// ========== CLOUDFLARE R2 ==========
const r2Client = new S3Client({
    region: 'auto',
    endpoint: process.env.R2_ENDPOINT || `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
    }
});

const R2_BUCKET = process.env.R2_BUCKET_NAME || 'storage';
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

console.log('✅ Cloudflare R2 initialized');

// ========== JWT MIDDLEWARE ==========
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Authentication required' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
};

const requireRole = (roles) => (req, res, next) => {
    if (!req.user) return res.status(401).json({ success: false, error: 'Authentication required' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ success: false, error: 'Insufficient permissions' });
    next();
};

// ========== CREATE DEFAULT ADMIN ==========
async function createDefaultAdmin() {
    try {
        const email = 'admin@vero.com';
        const password = 'admin123';
        const name = 'مدير النظام';
        
        try {
            await auth.getUserByEmail(email);
            console.log('✅ المستخدم admin@vero.com موجود بالفعل');
        } catch (error) {
            console.log('📝 جاري إنشاء المستخدم الافتراضي...');
            const userRecord = await auth.createUser({ email, password, displayName: name });
            await auth.setCustomUserClaims(userRecord.uid, { role: 'super_admin' });
            await db.collection('users').doc(userRecord.uid).set({
                uid: userRecord.uid,
                email,
                name,
                role: 'super_admin',
                status: 'active',
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            });
            console.log('✅ تم إنشاء المستخدم الافتراضي!');
            console.log('   📧 admin@vero.com | 🔑 admin123');
        }
    } catch (error) {
        console.error('❌ خطأ في إنشاء المستخدم:', error.message);
    }
}

// ========== HEALTH CHECK ==========
app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// ========== AUTH ==========
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password required' });
    }
    try {
        const userRecord = await auth.getUserByEmail(email);
        const userDoc = await db.collection('users').doc(userRecord.uid).get();
        const userData = userDoc.exists ? userDoc.data() : { role: 'client', tenantId: null };
        if (userData.status === 'suspended') {
            return res.status(403).json({ success: false, error: 'Account suspended' });
        }
        const token = jwt.sign(
            { uid: userRecord.uid, email, role: userData.role, tenantId: userData.tenantId, name: userRecord.displayName },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        res.json({
            success: true,
            token,
            user: {
                uid: userRecord.uid,
                email,
                displayName: userRecord.displayName,
                role: userData.role,
                tenantId: userData.tenantId
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
});

app.post('/api/auth/register', async (req, res) => {
    const { email, password, name, role = 'developer' } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password required' });
    }
    try {
        const userRecord = await auth.createUser({ email, password, displayName: name || email.split('@')[0] });
        await auth.setCustomUserClaims(userRecord.uid, { role });
        await db.collection('users').doc(userRecord.uid).set({
            uid: userRecord.uid,
            email,
            name: name || email.split('@')[0],
            role,
            status: 'active',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ success: true, message: 'User created successfully', uid: userRecord.uid });
    } catch (error) {
        console.error('Register error:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

// ========== UPDATE USER ROLE ==========
app.put('/api/users/:uid/role', verifyToken, async (req, res) => {
    const { uid } = req.params;
    const { role } = req.body;
    
    if (req.user.role !== 'super_admin') {
        return res.status(403).json({ success: false, error: 'Only super_admin can change roles' });
    }
    
    try {
        await auth.setCustomUserClaims(uid, { role });
        await db.collection('users').doc(uid).update({ 
            role, 
            updatedAt: admin.firestore.FieldValue.serverTimestamp() 
        });
        console.log(`✅ Updated user ${uid} role to ${role}`);
        res.json({ success: true, message: `Role updated to ${role}` });
    } catch (error) {
        console.error('Error updating role:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== PROJECTS ==========
app.get('/api/projects', verifyToken, async (req, res) => {
    try {
        let query = db.collection('projects');
        if (req.user.role === 'developer') query = query.where('assignedTo', '==', req.user.uid);
        const snapshot = await query.orderBy('createdAt', 'desc').get();
        res.json({ success: true, projects: snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) });
    } catch (error) {
        console.error('Projects error:', error);
        res.json({ success: true, projects: [] });
    }
});

app.post('/api/projects', verifyToken, requireRole(['super_admin', 'admin', 'developer']), async (req, res) => {
    const { name, clientId, html = '', css = '', js = '' } = req.body;
    if (!name) return res.status(400).json({ success: false, error: 'Project name required' });
    const projectRef = db.collection('projects').doc();
    await projectRef.set({
        id: projectRef.id,
        name,
        clientId: clientId || null,
        html,
        css,
        js,
        status: 'draft',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: req.user.uid
    });
    res.json({ success: true, id: projectRef.id });
});

app.get('/api/projects/:id', verifyToken, async (req, res) => {
    const doc = await db.collection('projects').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ success: false, error: 'Project not found' });
    res.json({ success: true, project: { id: doc.id, ...doc.data() } });
});

app.put('/api/projects/:id', verifyToken, requireRole(['super_admin', 'admin', 'developer']), async (req, res) => {
    const { html, css, js, name } = req.body;
    const updateData = {};
    if (html !== undefined) updateData.html = html;
    if (css !== undefined) updateData.css = css;
    if (js !== undefined) updateData.js = js;
    if (name !== undefined) updateData.name = name;
    updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    await db.collection('projects').doc(req.params.id).update(updateData);
    res.json({ success: true });
});

app.delete('/api/projects/:id', verifyToken, requireRole(['super_admin', 'admin']), async (req, res) => {
    await db.collection('projects').doc(req.params.id).delete();
    res.json({ success: true });
});

// ========== CLIENTS ==========
app.get('/api/clients', verifyToken, requireRole(['super_admin', 'admin']), async (req, res) => {
    try {
        const snapshot = await db.collection('clients').orderBy('createdAt', 'desc').get();
        res.json({ success: true, clients: snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) });
    } catch (error) {
        console.error('Clients error:', error);
        res.json({ success: true, clients: [] });
    }
});

app.post('/api/clients', verifyToken, requireRole(['super_admin', 'admin']), async (req, res) => {
    const { name, email, phone, plan = 'business' } = req.body;
    if (!name || !email) return res.status(400).json({ success: false, error: 'Name and email required' });
    const clientId = uuidv4();
    await db.collection('clients').doc(clientId).set({
        clientId, name, email, phone, plan, status: 'active',
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    res.json({ success: true, id: clientId });
});

app.delete('/api/clients/:id', verifyToken, requireRole(['super_admin', 'admin']), async (req, res) => {
    await db.collection('clients').doc(req.params.id).delete();
    res.json({ success: true });
});

// ========== WEBSITES ==========
app.get('/api/websites', verifyToken, requireRole(['super_admin', 'admin', 'developer']), async (req, res) => {
    try {
        const snapshot = await db.collection('websites').orderBy('publishedAt', 'desc').get();
        res.json({ success: true, websites: snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) });
    } catch (error) {
        console.error('Websites error:', error);
        res.json({ success: true, websites: [] });
    }
});

// ========== STATS ==========
app.get('/api/stats', verifyToken, async (req, res) => {
    try {
        const [clients, projects, websites] = await Promise.all([
            db.collection('clients').get(),
            db.collection('projects').get(),
            db.collection('websites').get()
        ]);
        res.json({
            success: true,
            stats: {
                totalClients: clients.size,
                totalProjects: projects.size,
                totalWebsites: websites.size
            }
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.json({ success: true, stats: { totalClients: 0, totalProjects: 0, totalWebsites: 0 } });
    }
});

// ========== DEPLOY ==========
app.post('/api/deploy', verifyToken, requireRole(['super_admin', 'admin', 'developer']), async (req, res) => {
    const { projectId, clientName, clientEmail, domain, plan } = req.body;
    const tempPassword = Math.random().toString(36).slice(-10);
    const tenantId = `tenant_${Date.now()}`;
    
    try {
        const projectDoc = await db.collection('projects').doc(projectId).get();
        if (!projectDoc.exists) {
            return res.status(404).json({ success: false, error: 'Project not found' });
        }
        const projectData = projectDoc.data();
        
        const html = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${projectData.name || clientName}</title>
    <style>body{font-family:Arial;margin:0;padding:20px;direction:rtl}</style>
    <style>${projectData.css || ''}</style>
</head>
<body>
    ${projectData.html || `<h1 data-vero-id="hero-title">مرحباً بك في ${clientName}</h1>`}
    <script>${projectData.js || ''}</script>
</body>
</html>`;
        
        const fileName = `${tenantId}/index.html`;
        await r2Client.send(new PutObjectCommand({
            Bucket: R2_BUCKET,
            Key: fileName,
            Body: html,
            ContentType: 'text/html'
        }));
        
        let userRecord;
        try {
            userRecord = await auth.createUser({ email: clientEmail, password: tempPassword, displayName: clientName });
        } catch(e) {
            userRecord = await auth.getUserByEmail(clientEmail);
        }
        await auth.setCustomUserClaims(userRecord.uid, { role: 'client', tenantId });
        
        const websiteDomain = domain || `${tenantId}.verocomp.com`;
        await db.collection('websites').doc(tenantId).set({
            tenantId, projectId, name: clientName, domain: websiteDomain,
            r2Path: fileName, status: 'active',
            publishedAt: admin.firestore.FieldValue.serverTimestamp(),
            publishedBy: req.user.uid
        });
        
        await db.collection('clients').doc(tenantId).set({
            clientId: tenantId, userId: userRecord.uid, name: clientName,
            email: clientEmail, plan: plan || 'business', status: 'active',
            websiteDomain, createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        const websiteUrl = `${R2_PUBLIC_URL}/${fileName}`;
        
        res.json({
            success: true,
            client: { email: clientEmail, password: tempPassword, tenantId, websiteUrl }
        });
    } catch (error) {
        console.error('Deploy error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== ACTIVITY ==========
app.get('/api/activity', verifyToken, async (req, res) => {
    try {
        const snapshot = await db.collection('activityLogs').orderBy('timestamp', 'desc').limit(100).get();
        res.json({ success: true, logs: snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) });
    } catch (error) {
        console.error('Activity error:', error);
        res.json({ success: true, logs: [] });
    }
});

// ========== BACKUPS ==========
app.get('/api/backups/:projectId', verifyToken, async (req, res) => {
    try {
        const snapshot = await db.collection('backups').where('projectId', '==', req.params.projectId).orderBy('createdAt', 'desc').get();
        res.json({ success: true, backups: snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) });
    } catch (error) {
        console.error('Backups error:', error);
        res.json({ success: true, backups: [] });
    }
});

// ============================================================
// ========== REALTIME DATABASE (RTDB) API ==========
// ============================================================

// RTDB: جلب كل بيانات العميل
app.get('/api/rtdb/client/:tenantId', verifyToken, async (req, res) => {
    const { tenantId } = req.params;
    
    if (req.user.role !== 'super_admin' && req.user.tenantId !== tenantId && req.user.tenantId !== 'agency') {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    try {
        const snapshot = await rtdb.ref(`tenants/${tenantId}`).once('value');
        const data = snapshot.val() || {};
        res.json({ success: true, data, tenantId, lastUpdated: new Date().toISOString() });
    } catch (error) {
        console.error('RTDB get error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// RTDB: جلب مسار محدد (باستخدام query parameter بدلاً من wildcard)
app.get('/api/rtdb/client/:tenantId/path', verifyToken, async (req, res) => {
    const { tenantId } = req.params;
    const path = req.query.path || '';
    
    if (req.user.role !== 'super_admin' && req.user.tenantId !== tenantId && req.user.tenantId !== 'agency') {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    try {
        const snapshot = await rtdb.ref(`tenants/${tenantId}/${path}`).once('value');
        const data = snapshot.val();
        res.json({ success: true, data, path, tenantId });
    } catch (error) {
        console.error('RTDB get path error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// RTDB: حفظ/تحديث بيانات العميل بالكامل
app.put('/api/rtdb/client/:tenantId', verifyToken, async (req, res) => {
    const { tenantId } = req.params;
    const { data } = req.body;
    
    if (req.user.role !== 'super_admin' && req.user.tenantId !== tenantId && req.user.tenantId !== 'agency') {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    if (!data) {
        return res.status(400).json({ success: false, error: 'Data is required' });
    }
    
    try {
        await rtdb.ref(`tenants/${tenantId}`).set(data);
        
        await db.collection('activityLogs').add({
            action: 'RTDB_UPDATE_ALL',
            tenantId,
            userId: req.user.uid,
            userEmail: req.user.email,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
        
        res.json({ success: true, message: 'Client data saved successfully', tenantId, updatedAt: new Date().toISOString() });
    } catch (error) {
        console.error('RTDB set error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// RTDB: تحديث عنصر واحد (باستخدام query parameter)
app.patch('/api/rtdb/client/:tenantId/element', verifyToken, async (req, res) => {
    const { tenantId } = req.params;
    const { path, value } = req.body;
    
    if (req.user.role !== 'super_admin' && req.user.tenantId !== tenantId && req.user.tenantId !== 'agency') {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    if (!path || value === undefined) {
        return res.status(400).json({ success: false, error: 'Path and value are required' });
    }
    
    try {
        await rtdb.ref(`tenants/${tenantId}/${path}`).set(value);
        
        await db.collection('activityLogs').add({
            action: 'RTDB_UPDATE_ELEMENT',
            tenantId,
            path,
            userId: req.user.uid,
            userEmail: req.user.email,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
        
        res.json({ success: true, message: 'Element updated successfully', tenantId, path, value });
    } catch (error) {
        console.error('RTDB patch error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// RTDB: حذف مسار (باستخدام query parameter)
app.delete('/api/rtdb/client/:tenantId/path', verifyToken, async (req, res) => {
    const { tenantId } = req.params;
    const path = req.query.path || '';
    
    if (req.user.role !== 'super_admin' && req.user.tenantId !== tenantId && req.user.tenantId !== 'agency') {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    if (!path) {
        return res.status(400).json({ success: false, error: 'Path is required' });
    }
    
    try {
        await rtdb.ref(`tenants/${tenantId}/${path}`).remove();
        res.json({ success: true, message: `Path "${path}" deleted successfully`, tenantId });
    } catch (error) {
        console.error('RTDB delete error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// RTDB: الحصول على جميع الـ tenants
app.get('/api/rtdb/tenants', verifyToken, requireRole(['super_admin']), async (req, res) => {
    try {
        const snapshot = await rtdb.ref('tenants').once('value');
        const tenants = snapshot.val() || {};
        const stats = { totalTenants: Object.keys(tenants).length, tenantsList: Object.keys(tenants) };
        res.json({ success: true, tenants, stats });
    } catch (error) {
        console.error('RTDB get tenants error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// RTDB: حذف tenant بالكامل
app.delete('/api/rtdb/tenant/:tenantId', verifyToken, requireRole(['super_admin']), async (req, res) => {
    const { tenantId } = req.params;
    try {
        await rtdb.ref(`tenants/${tenantId}`).remove();
        res.json({ success: true, message: `Tenant "${tenantId}" deleted successfully` });
    } catch (error) {
        console.error('RTDB delete tenant error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// RTDB: استماع للتغييرات (SSE)
app.get('/api/rtdb/subscribe/:tenantId', verifyToken, async (req, res) => {
    const { tenantId } = req.params;
    
    if (req.user.role !== 'super_admin' && req.user.tenantId !== tenantId && req.user.tenantId !== 'agency') {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
    });
    
    const heartbeat = setInterval(() => res.write(`: heartbeat\n\n`), 30000);
    
    const ref = rtdb.ref(`tenants/${tenantId}`);
    const listener = ref.on('value', (snapshot) => {
        const data = snapshot.val();
        res.write(`event: update\n`);
        res.write(`data: ${JSON.stringify({ data, timestamp: new Date().toISOString() })}\n\n`);
    });
    
    req.on('close', () => {
        clearInterval(heartbeat);
        ref.off('value', listener);
        res.end();
    });
});

// RTDB: نسخ احتياطي
app.post('/api/rtdb/backup/:tenantId', verifyToken, requireRole(['super_admin', 'admin']), async (req, res) => {
    const { tenantId } = req.params;
    try {
        const snapshot = await rtdb.ref(`tenants/${tenantId}`).once('value');
        const data = snapshot.val();
        
        if (!data) {
            return res.status(404).json({ success: false, error: 'Tenant not found' });
        }
        
        const backupId = `backup_${Date.now()}`;
        await db.collection('rtdbBackups').doc(backupId).set({
            backupId, tenantId, data, createdBy: req.user.uid, createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        res.json({ success: true, backupId, message: 'Backup created successfully', backupSize: JSON.stringify(data).length });
    } catch (error) {
        console.error('RTDB backup error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// RTDB: استعادة نسخة
app.post('/api/rtdb/restore/:tenantId/:backupId', verifyToken, requireRole(['super_admin']), async (req, res) => {
    const { tenantId, backupId } = req.params;
    try {
        const backupDoc = await db.collection('rtdbBackups').doc(backupId).get();
        
        if (!backupDoc.exists) {
            return res.status(404).json({ success: false, error: 'Backup not found' });
        }
        
        const backup = backupDoc.data();
        
        if (backup.tenantId !== tenantId) {
            return res.status(400).json({ success: false, error: 'Backup tenant mismatch' });
        }
        
        await rtdb.ref(`tenants/${tenantId}`).set(backup.data);
        res.json({ success: true, message: `Restored from backup ${backupId}`, restoredAt: new Date().toISOString() });
    } catch (error) {
        console.error('RTDB restore error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== TEMPLATES ==========
app.get('/api/templates', verifyToken, async (req, res) => {
    try {
        const snapshot = await db.collection('templates').get();
        res.json({ success: true, templates: snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) });
    } catch (error) {
        console.error('Templates error:', error);
        res.json({ success: true, templates: [] });
    }
});

// ========== DOMAINS ==========
app.get('/api/domains', verifyToken, async (req, res) => {
    try {
        const snapshot = await db.collection('domains').where('tenantId', '==', req.user.tenantId || 'agency').get();
        res.json({ success: true, domains: snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) });
    } catch (error) {
        console.error('Domains error:', error);
        res.json({ success: true, domains: [] });
    }
});

// ========== TEAM ==========
app.get('/api/team', verifyToken, requireRole(['super_admin', 'admin']), async (req, res) => {
    try {
        const snapshot = await db.collection('users').get();
        res.json({ success: true, users: snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) });
    } catch (error) {
        console.error('Team error:', error);
        res.json({ success: true, users: [] });
    }
});

// ========== R2 STORAGE API ==========
app.get('/api/r2/buckets', verifyToken, requireRole(['super_admin', 'admin']), async (req, res) => {
    try {
        res.json({
            success: true,
            buckets: [
                { name: 'vero-websites', region: 'auto', createdAt: '2024-01-01' },
                { name: 'vero-assets', region: 'auto', createdAt: '2024-01-01' },
                { name: 'vero-backups', region: 'auto', createdAt: '2024-01-01' }
            ]
        });
    } catch (error) {
        console.error('R2 buckets error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/r2/objects', verifyToken, async (req, res) => {
    const { bucket, prefix = '' } = req.query;
    try {
        const command = new ListObjectsV2Command({
            Bucket: bucket || R2_BUCKET,
            Prefix: prefix
        });
        const response = await r2Client.send(command);
        const objects = (response.Contents || []).map(obj => ({
            key: obj.Key,
            size: obj.Size,
            lastModified: obj.LastModified
        }));
        res.json({ success: true, objects });
    } catch (error) {
        console.error('R2 objects error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/r2/upload', verifyToken, upload.single('file'), async (req, res) => {
    const { bucket = R2_BUCKET, folder = 'uploads' } = req.body;
    const file = req.file;
    
    if (!file) {
        return res.status(400).json({ success: false, error: 'No file uploaded' });
    }
    
    const key = `${folder}/${Date.now()}_${file.originalname}`;
    
    try {
        await r2Client.send(new PutObjectCommand({
            Bucket: bucket,
            Key: key,
            Body: file.buffer,
            ContentType: file.mimetype
        }));
        
        const fileUrl = `${R2_PUBLIC_URL}/${key}`;
        
        res.json({
            success: true,
            file: { key, url: fileUrl, size: file.size, mimeType: file.mimetype, name: file.originalname }
        });
    } catch (error) {
        console.error('R2 upload error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/r2/objects', verifyToken, async (req, res) => {
    const { bucket = R2_BUCKET, key } = req.body;
    if (!key) {
        return res.status(400).json({ success: false, error: 'Key is required' });
    }
    
    try {
        await r2Client.send(new DeleteObjectCommand({
            Bucket: bucket,
            Key: key
        }));
        res.json({ success: true });
    } catch (error) {
        console.error('R2 delete error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== CLIENT CONTENT API ==========
app.get('/api/client/content/:tenantId', verifyToken, async (req, res) => {
    const { tenantId } = req.params;
    
    if (req.user.role !== 'super_admin' && req.user.tenantId !== tenantId) {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    try {
        const snapshot = await db.collection('clientContent').doc(tenantId).get();
        res.json({ success: true, content: snapshot.exists ? snapshot.data() : {} });
    } catch (error) {
        console.error('Client content error:', error);
        res.json({ success: true, content: {} });
    }
});

app.put('/api/client/content/:tenantId/element', verifyToken, async (req, res) => {
    const { tenantId } = req.params;
    const { elementId, value } = req.body;
    
    if (req.user.role !== 'super_admin' && req.user.tenantId !== tenantId) {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    try {
        await db.collection('clientContent').doc(tenantId).set({
            [elementId]: value,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        res.json({ success: true });
    } catch (error) {
        console.error('Update client content error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== CLIENT MEDIA API ==========
app.get('/api/client/media', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const prefix = `clients/${tenantId}/`;
    
    try {
        const command = new ListObjectsV2Command({
            Bucket: R2_BUCKET,
            Prefix: prefix
        });
        const response = await r2Client.send(command);
        const files = (response.Contents || []).map(obj => ({
            id: obj.Key,
            key: obj.Key,
            name: obj.Key.split('/').pop(),
            url: `${R2_PUBLIC_URL}/${obj.Key}`,
            size: obj.Size,
            lastModified: obj.LastModified
        }));
        res.json({ success: true, files });
    } catch (error) {
        console.error('Client media error:', error);
        res.json({ success: true, files: [] });
    }
});

app.post('/api/client/media/upload', verifyToken, upload.single('file'), async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const file = req.file;
    
    if (!file) {
        return res.status(400).json({ success: false, error: 'No file uploaded' });
    }
    
    const key = `clients/${tenantId}/${Date.now()}_${file.originalname}`;
    
    try {
        await r2Client.send(new PutObjectCommand({
            Bucket: R2_BUCKET,
            Key: key,
            Body: file.buffer,
            ContentType: file.mimetype
        }));
        
        res.json({
            success: true,
            file: {
                id: key,
                key: key,
                name: file.originalname,
                url: `${R2_PUBLIC_URL}/${key}`,
                size: file.size,
                mimeType: file.mimetype
            }
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/client/media/:key', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const key = req.params.key;
    
    if (!key.startsWith(`clients/${tenantId}/`)) {
        return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    try {
        await r2Client.send(new DeleteObjectCommand({
            Bucket: R2_BUCKET,
            Key: key
        }));
        res.json({ success: true });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== CLIENT PRODUCTS API ==========
app.get('/api/client/products', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    try {
        const snapshot = await db.collection('clients').doc(tenantId).collection('products').get();
        const products = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json({ success: true, products });
    } catch (error) {
        console.error('Products error:', error);
        res.json({ success: true, products: [] });
    }
});

app.post('/api/client/products', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const { name, price, discountPrice, stock, sku, image, description } = req.body;
    
    if (!name || !price) {
        return res.status(400).json({ success: false, error: 'Name and price required' });
    }
    
    const productId = uuidv4();
    try {
        await db.collection('clients').doc(tenantId).collection('products').doc(productId).set({
            id: productId, name, price, discountPrice: discountPrice || null, stock: stock || 0,
            sku: sku || '', image: image || '', description: description || '',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ success: true, id: productId });
    } catch (error) {
        console.error('Create product error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/client/products/:id', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const { id } = req.params;
    const { name, price, discountPrice, stock, sku, image, description } = req.body;
    
    try {
        await db.collection('clients').doc(tenantId).collection('products').doc(id).update({
            name, price, discountPrice: discountPrice || null, stock: stock || 0,
            sku, image, description,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/client/products/:id', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const { id } = req.params;
    try {
        await db.collection('clients').doc(tenantId).collection('products').doc(id).delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== CLIENT ORDERS API ==========
app.get('/api/client/orders', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    try {
        const snapshot = await db.collection('clients').doc(tenantId).collection('orders').orderBy('createdAt', 'desc').get();
        const orders = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json({ success: true, orders });
    } catch (error) {
        console.error('Orders error:', error);
        res.json({ success: true, orders: [] });
    }
});

// ========== CLIENT BLOG API ==========
app.get('/api/client/blog', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    try {
        const snapshot = await db.collection('clients').doc(tenantId).collection('blog').orderBy('createdAt', 'desc').get();
        const posts = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json({ success: true, posts });
    } catch (error) {
        console.error('Blog error:', error);
        res.json({ success: true, posts: [] });
    }
});

app.post('/api/client/blog', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const { title_ar, title_en, content_ar, content_en, category, status, image } = req.body;
    
    if (!title_ar) {
        return res.status(400).json({ success: false, error: 'Title required' });
    }
    
    const postId = uuidv4();
    try {
        await db.collection('clients').doc(tenantId).collection('blog').doc(postId).set({
            id: postId, title_ar, title_en: title_en || '', content_ar, content_en: content_en || '',
            category: category || 'general', status: status || 'draft', image: image || '',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ success: true, id: postId });
    } catch (error) {
        console.error('Create post error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/client/blog/:id', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const { id } = req.params;
    const { title_ar, title_en, content_ar, content_en, category, status, image } = req.body;
    
    try {
        await db.collection('clients').doc(tenantId).collection('blog').doc(id).update({
            title_ar, title_en, content_ar, content_en, category, status, image,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Update post error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/client/blog/:id', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const { id } = req.params;
    try {
        await db.collection('clients').doc(tenantId).collection('blog').doc(id).delete();
        res.json({ success: true });
    } catch (error) {
        console.error('Delete post error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/client/blog/:id/publish', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const { id } = req.params;
    try {
        await db.collection('clients').doc(tenantId).collection('blog').doc(id).update({
            status: 'published',
            publishedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Publish post error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== CLIENT TICKETS API ==========
app.get('/api/client/tickets', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    try {
        const snapshot = await db.collection('clients').doc(tenantId).collection('tickets').orderBy('createdAt', 'desc').get();
        const tickets = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json({ success: true, tickets });
    } catch (error) {
        console.error('Tickets error:', error);
        res.json({ success: true, tickets: [] });
    }
});

app.post('/api/client/tickets', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const { title, message } = req.body;
    
    if (!title || !message) {
        return res.status(400).json({ success: false, error: 'Title and message required' });
    }
    
    const ticketId = uuidv4();
    try {
        await db.collection('clients').doc(tenantId).collection('tickets').doc(ticketId).set({
            id: ticketId, title, message, status: 'open',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            createdBy: req.user.uid
        });
        res.json({ success: true, id: ticketId });
    } catch (error) {
        console.error('Create ticket error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== CLIENT ANALYTICS API ==========
app.get('/api/client/analytics', verifyToken, async (req, res) => {
    const tenantId = req.user.tenantId || 'agency';
    const { period = 'week' } = req.query;
    
    const mockData = {
        week: {
            totalVisitors: 2450, totalOrders: 128, totalRevenue: 45230, conversionRate: 5.2,
            visitorsLabels: ['أحد', 'إثنين', 'ثلاثاء', 'أربعاء', 'خميس', 'جمعة', 'سبت'],
            visitorsData: [280, 320, 350, 380, 420, 450, 250],
            salesLabels: ['أحد', 'إثنين', 'ثلاثاء', 'أربعاء', 'خميس', 'جمعة', 'سبت'],
            salesData: [5200, 6100, 6800, 7200, 8500, 9100, 3300],
            topProducts: [{ name: 'منتج 1', quantity: 45 }, { name: 'منتج 2', quantity: 32 }, { name: 'منتج 3', quantity: 28 }]
        },
        month: {
            totalVisitors: 10200, totalOrders: 485, totalRevenue: 185000, conversionRate: 4.8,
            visitorsLabels: ['أسبوع 1', 'أسبوع 2', 'أسبوع 3', 'أسبوع 4'],
            visitorsData: [2200, 2450, 2680, 2870],
            salesLabels: ['أسبوع 1', 'أسبوع 2', 'أسبوع 3', 'أسبوع 4'],
            salesData: [38500, 42800, 46500, 51200],
            topProducts: [{ name: 'منتج 1', quantity: 120 }, { name: 'منتج 2', quantity: 95 }, { name: 'منتج 3', quantity: 78 }]
        },
        year: {
            totalVisitors: 125000, totalOrders: 5840, totalRevenue: 2240000, conversionRate: 4.7,
            visitorsLabels: ['يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو', 'يوليو', 'أغسطس', 'سبتمبر', 'أكتوبر', 'نوفمبر', 'ديسمبر'],
            visitorsData: [8500, 9200, 10100, 11200, 11800, 12500, 13200, 12800, 11900, 10500, 9800, 9100],
            salesLabels: ['يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو', 'يوليو', 'أغسطس', 'سبتمبر', 'أكتوبر', 'نوفمبر', 'ديسمبر'],
            salesData: [152000, 168000, 185000, 198000, 205000, 212000, 218000, 205000, 195000, 178000, 165000, 158000],
            topProducts: [{ name: 'منتج 1', quantity: 520 }, { name: 'منتج 2', quantity: 445 }, { name: 'منتج 3', quantity: 380 }]
        }
    };
    
    res.json({ success: true, ...mockData[period] });
});

// ========== CLIENT PROFILE API ==========
app.put('/api/client/profile', verifyToken, async (req, res) => {
    const { displayName, phone, company } = req.body;
    try {
        await auth.updateUser(req.user.uid, { displayName });
        await db.collection('users').doc(req.user.uid).update({
            name: displayName,
            phone,
            company,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================
// ========== SERVE STATIC FILES ==========
// ============================================================

// 1. الموقع العام
const publicPath = path.join(__dirname, 'public');
if (fs.existsSync(publicPath)) {
    app.use('/', express.static(publicPath));
    console.log('✅ Serving public website from:', publicPath);
} else {
    console.log('⚠️ Public folder not found:', publicPath);
}

// 2. Client dashboard
const clientPath = path.join(__dirname, 'client');
if (fs.existsSync(clientPath)) {
    app.use('/client', express.static(clientPath));
    console.log('✅ Serving client dashboard from:', clientPath);
} else {
    console.log('⚠️ Client folder not found:', clientPath);
}

// 3. Studio dashboard (VERO Studio)
const studioPath = path.join(__dirname, 'studio');
if (fs.existsSync(studioPath)) {
    app.use('/studio', express.static(studioPath));
    console.log('✅ Serving VERO Studio from:', studioPath);
} else {
    console.log('⚠️ Studio folder not found:', studioPath);
}

// الصفحة الرئيسية الافتراضية
app.get('/', (req, res) => {
    const indexPath = path.join(publicPath, 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>VERO API</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #e7c27a;">VERO API</h1>
                <p>API is running successfully!</p>
                <p>📡 <a href="/api/health">/api/health</a></p>
                <p>🔐 Login: admin@vero.com / admin123</p>
                <hr>
                <h3>Available Routes:</h3>
                <ul style="list-style: none; padding: 0;">
                    <li>📡 <a href="/api/health">/api/health</a> - Health check</li>
                    <li>🔐 <a href="/api/auth/login">POST /api/auth/login</a> - Login</li>
                    <li>📁 <a href="/api/projects">/api/projects</a> - Projects</li>
                    <li>👥 <a href="/api/clients">/api/clients</a> - Clients</li>
                    <li>📊 <a href="/api/stats">/api/stats</a> - Statistics</li>
                </ul>
                <hr>
                <p>🌐 <a href="/">Public Website</a> | 👤 <a href="/client/dashboard.html">Client Dashboard</a> | 🛠 <a href="/studio/login.html">VERO Studio</a></p>
            </body>
            </html>
        `);
    }
});

// ========== START SERVER ==========
app.listen(PORT, async () => {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`🚀 VERO Backend running on port ${PORT}`);
    console.log(`📡 API: http://localhost:${PORT}/api`);
    console.log(`✅ Health check: http://localhost:${PORT}/api/health`);
    console.log(`🌐 Public website: http://localhost:${PORT}/`);
    console.log(`👤 Client dashboard: http://localhost:${PORT}/client/dashboard.html`);
    console.log(`🛠 VERO Studio: http://localhost:${PORT}/studio/login.html`);
    console.log(`${'='.repeat(60)}\n`);
    
    console.log('📁 Static file paths:');
    console.log(`   Public: ${publicPath} (exists: ${fs.existsSync(publicPath)})`);
    console.log(`   Client: ${clientPath} (exists: ${fs.existsSync(clientPath)})`);
    console.log(`   Studio: ${studioPath} (exists: ${fs.existsSync(studioPath)})`);
    console.log('');
    
    await createDefaultAdmin();
});