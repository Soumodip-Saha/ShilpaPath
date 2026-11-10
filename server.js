// Sanskriti - Lightweight RESTful Node.js Server
// Zero external npm dependencies required (uses built-in http, fs, path, url)
// Follows System Design principles: stateless REST, clean separation, low latency, robust file persistence

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const ADMIN_PIN = '1947'; // Master Admin PIN for cultural custodians

// Ensure data file exists
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
    }
  } catch (err) {
    console.error('Error reading data file:', err);
  }
  return { clusters: [], routes: [], defaultPendingPlans: [], defaultMemories: [], defaultSubmissions: [] };
}

function saveData(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf-8');
    return true;
  } catch (err) {
    console.error('Error saving data file:', err);
    return false;
  }
}

// In-memory working state initialized from persistent data.json
let database = loadData();

// MIME Types for static files
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.mp3': 'audio/mpeg'
};

// Helper: send JSON response with CORS headers
function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(payload));
}

// Helper: parse JSON request body
function parseBody(req, callback) {
  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
    if (body.length > 10 * 1024 * 1024) { // 10MB limit for base64 photo uploads
      req.connection.destroy();
    }
  });
  req.on('end', () => {
    try {
      const data = body ? JSON.parse(body) : {};
      callback(null, data);
    } catch (err) {
      callback(err, null);
    }
  });
}

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Handle CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end();
    return;
  }

  // --- API Endpoints ---

  // 1. Full Data Store (Read-Through Cache)
  if (pathname === '/api/data' && method === 'GET') {
    return sendJson(res, 200, database);
  }

  // 2. Clusters / Sites list
  if (pathname === '/api/sites' && method === 'GET') {
    return sendJson(res, 200, { success: true, count: database.clusters.length, sites: database.clusters });
  }

  // 3. Artisans Directory
  if (pathname === '/api/artisans' && method === 'GET') {
    const artisans = database.clusters.map(c => ({
      ...c.artisan,
      clusterId: c.id,
      clusterName: c.name,
      craft: c.craft,
      state: c.state,
      tag: c.tag
    }));
    return sendJson(res, 200, { success: true, count: artisans.length, artisans });
  }

  // 4. Pending Travel Plans
  if (pathname === '/api/plans') {
    if (method === 'GET') {
      return sendJson(res, 200, { success: true, plans: database.defaultPendingPlans || [] });
    }
    if (method === 'POST') {
      return parseBody(req, (err, plan) => {
        if (err || !plan.title) {
          return sendJson(res, 400, { success: false, message: 'Invalid plan data' });
        }
        plan.id = 'plan-' + Date.now();
        plan.createdAt = new Date().toISOString();
        if (!database.defaultPendingPlans) database.defaultPendingPlans = [];
        database.defaultPendingPlans.unshift(plan);
        saveData(database);
        return sendJson(res, 201, { success: true, plan });
      });
    }
  }

  // Delete plan
  if (pathname.startsWith('/api/plans/') && method === 'DELETE') {
    const planId = pathname.replace('/api/plans/', '');
    database.defaultPendingPlans = (database.defaultPendingPlans || []).filter(p => p.id !== planId);
    saveData(database);
    return sendJson(res, 200, { success: true, message: 'Plan removed' });
  }

  // 5. Memories & Travel Photos
  if (pathname === '/api/memories') {
    if (method === 'GET') {
      return sendJson(res, 200, { success: true, memories: database.defaultMemories || [] });
    }
    if (method === 'POST') {
      return parseBody(req, (err, memory) => {
        if (err || !memory.placeName || !memory.travelDate) {
          return sendJson(res, 400, { success: false, message: 'Place name and travel date are required' });
        }
        memory.id = 'mem-' + Date.now();
        memory.status = 'pending'; // Requires Admin Verification within 48 hrs SLA
        memory.submittedHoursAgo = 0;
        memory.slaRemainingHours = 48;
        memory.submittedAt = new Date().toISOString();
        if (!database.defaultMemories) database.defaultMemories = [];
        database.defaultMemories.unshift(memory);
        saveData(database);
        return sendJson(res, 201, {
          success: true,
          message: 'Memory uploaded! Submitted for curator verification (48-hr SLA).',
          memory
        });
      });
    }
  }

  // 6. Suggest Unlisted Place Submissions
  if (pathname === '/api/places' && method === 'POST') {
    return parseBody(req, (err, submission) => {
      if (err || !submission.name || !submission.state || !submission.craft) {
        return sendJson(res, 400, { success: false, message: 'Missing required place details' });
      }
      submission.id = 'sub-' + Date.now();
      submission.status = 'pending'; // Requires Admin Verification within 24-36 hrs SLA
      submission.submittedHoursAgo = 0;
      submission.slaRemainingHours = 36;
      submission.submittedAt = new Date().toISOString();
      if (!database.defaultSubmissions) database.defaultSubmissions = [];
      database.defaultSubmissions.unshift(submission);
      saveData(database);
      return sendJson(res, 201, {
        success: true,
        message: 'New heritage place submitted! Under verification by cultural committee (24-36 hrs SLA).',
        submission
      });
    });
  }

  // 7. Admin Authentication
  if (pathname === '/api/admin/login' && method === 'POST') {
    return parseBody(req, (err, data) => {
      if (data && data.pin === ADMIN_PIN) {
        return sendJson(res, 200, { success: true, token: 'admin-authorized-token' });
      }
      return sendJson(res, 401, { success: false, message: 'Invalid Admin PIN' });
    });
  }

  // 8. Admin Moderation: Verify / Reject Memory
  if (pathname === '/api/admin/verify-memory' && method === 'POST') {
    return parseBody(req, (err, data) => {
      if (!data || data.pin !== ADMIN_PIN) {
        return sendJson(res, 401, { success: false, message: 'Unauthorized action' });
      }
      const memIndex = (database.defaultMemories || []).findIndex(m => m.id === data.memoryId);
      if (memIndex === -1) {
        return sendJson(res, 404, { success: false, message: 'Memory not found' });
      }

      if (data.action === 'approve') {
        database.defaultMemories[memIndex].status = 'verified';
        database.defaultMemories[memIndex].verifiedBy = 'Sanskriti Admin Team';
        database.defaultMemories[memIndex].verifiedAt = new Date().toISOString();
      } else if (data.action === 'reject') {
        database.defaultMemories[memIndex].status = 'rejected';
      }
      saveData(database);
      return sendJson(res, 200, { success: true, memory: database.defaultMemories[memIndex] });
    });
  }

  // 9. Admin Moderation: Verify / Reject New Place
  if (pathname === '/api/admin/verify-place' && method === 'POST') {
    return parseBody(req, (err, data) => {
      if (!data || data.pin !== ADMIN_PIN) {
        return sendJson(res, 401, { success: false, message: 'Unauthorized action' });
      }
      const subIndex = (database.defaultSubmissions || []).findIndex(s => s.id === data.submissionId);
      if (subIndex === -1) {
        return sendJson(res, 404, { success: false, message: 'Submission not found' });
      }

      const item = database.defaultSubmissions[subIndex];
      if (data.action === 'approve') {
        item.status = 'verified';
        item.verifiedBy = 'Sanskriti Cultural Committee';
        
        // Add to active clusters so it immediately renders on the map!
        const newCluster = {
          id: 'cluster-' + item.id,
          name: item.name,
          region: item.region || item.state,
          state: item.state,
          craft: item.craft,
          tag: 'Community Verified',
          lat: parseFloat(item.lat) || 23.5,
          lng: parseFloat(item.lng) || 87.0,
          visitingHours: '09:00 AM – 06:00 PM',
          bestSeason: 'Year Round',
          heroImage: item.photo || 'https://images.unsplash.com/photo-1599661046289-e31897846e41?auto=format&fit=crop&w=1000&q=80',
          gallery: [item.photo || 'https://images.unsplash.com/photo-1599661046289-e31897846e41?auto=format&fit=crop&w=800&q=80'],
          route: 'community-discoveries',
          historicalContext: item.description || 'Recently discovered community craft workshop verified by Sanskriti custodians.',
          craftTechnique: 'Preserved regional handicraft practiced by local indigenous masters.',
          i18n: {
            en: {
              title: item.name,
              shortDesc: item.craft + ' cluster in ' + (item.region || item.state),
              audioText: `Welcome to ${item.name}. This is a newly verified craft center producing authentic ${item.craft}.`
            },
            bn: {
              title: item.name,
              shortDesc: item.craft + ' - ' + (item.region || item.state),
              audioText: `${item.name}-এ আপনাকে স্বাগতম। এটি একটি নতুন অনুমোদিত ঐতিহ্যবাহী কুটির শিল্প কেন্দ্র।`
            },
            hi: {
              title: item.name,
              shortDesc: item.craft + ' - ' + (item.region || item.state),
              audioText: `${item.name} में आपका स्वागत है। यह एक नव-सत्यापित पारंपरिक शिल्प केंद्र है।`
            }
          },
          artisan: {
            id: 'artisan-' + item.id,
            name: item.artisanName || 'Master Craftsman',
            badge: 'Community Verified Artisan',
            pehchanId: 'PEHCHAN-PENDING',
            experience: 'Local Master',
            village: item.region || item.state,
            phone: item.artisanPhone || '919876543210',
            avatar: 'https://images.unsplash.com/photo-1544005313-94ddf0286df2?auto=format&fit=crop&w=300&q=80',
            pricing: {
              workshop: '₹350 / person (Live Workshop Experience)',
              product: 'Direct Artisan Fair Price'
            },
            specialty: item.craft
          }
        };
        database.clusters.push(newCluster);
      } else if (data.action === 'reject') {
        item.status = 'rejected';
      }
      saveData(database);
      return sendJson(res, 200, { success: true, submission: item });
    });
  }

  // --- Static Files Serving ---
  let safePath = pathname === '/' ? '/index.html' : pathname;
  // If requesting /data.json, serve directly from root or public
  let filePath = path.join(PUBLIC_DIR, safePath);
  if (safePath === '/data.json') {
    filePath = DATA_FILE;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Fallback to index.html for client-side routing
      const fallbackPath = path.join(PUBLIC_DIR, 'index.html');
      fs.readFile(fallbackPath, (fallbackErr, content) => {
        if (fallbackErr) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('404 Not Found');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(content);
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Server Error');
        return;
      }
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    });
  });
});

function startServer(portToTry) {
  server.listen(portToTry, () => {
    console.log(`====================================================`);
    console.log(`  Sanskriti Cultural & Artisan Trail Server Running  `);
    console.log(`  URL: http://localhost:${portToTry}                 `);
    console.log(`  Admin PIN: ${ADMIN_PIN}                            `);
    console.log(`====================================================`);
  });
}

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    const nextPort = Number(err.port || PORT) + 1;
    console.warn(`Port in use, automatically retrying on port ${nextPort}...`);
    startServer(nextPort);
  } else {
    console.error('Server error:', err);
  }
});

startServer(PORT);
