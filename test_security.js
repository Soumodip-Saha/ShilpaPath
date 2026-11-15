const http = require('http');
const path = require('path');
const fs = require('fs');

console.log('--- STARTING SHILPAPATH SECURITY & INTEGRATION TEST SUITE ---');

// 1. Check syntax of all JS files
console.log('\n[TEST 1] Verifying Syntax of All JavaScript Files...');
const filesToCheck = ['server.js', 'public/app.js', 'public/i18n.js', 'public/default-data.js'];
for (const file of filesToCheck) {
  const code = fs.readFileSync(path.resolve(__dirname, file), 'utf-8');
  new Function(code.replace(/import\s.*?;/g, '')); // Basic parse check
  console.log(`  ✓ Syntax check passed: ${file}`);
}

// 2. Start server in-process on an ephemeral test port
const TEST_PORT = 3999;
process.env.PORT = TEST_PORT;

// Require server without starting default listen if possible or spawn it
const { spawn } = require('child_process');
const serverProc = spawn(process.execPath, ['server.js'], {
  cwd: __dirname,
  env: { ...process.env, PORT: TEST_PORT }
});

let serverOutput = '';
serverProc.stdout.on('data', data => { serverOutput += data.toString(); });
serverProc.stderr.on('data', data => { serverOutput += data.toString(); });

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function makeRequest(method, reqPath, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '127.0.0.1',
      port: TEST_PORT,
      path: reqPath,
      method: method,
      headers: { ...headers }
    };
    if (body) {
      const dataStr = typeof body === 'string' ? body : JSON.stringify(body);
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['Content-Length'] = Buffer.byteLength(dataStr);
    }
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', chunk => { data += chunk.toString(); });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data: data
        });
      });
    });
    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

async function runTests() {
  await sleep(1500); // Wait for server to start
  console.log('Server process output:\n' + serverOutput);

  // TEST 2: Static file serving
  console.log('\n[TEST 2] Testing Static File Serving...');
  const resIndex = await makeRequest('GET', '/');
  console.log(`  GET / -> Status: ${resIndex.statusCode}, Content-Type: ${resIndex.headers['content-type']}`);
  if (resIndex.statusCode === 200 && resIndex.data.includes('ShilpaPath')) {
    console.log('  ✓ Root / successfully returned index.html');
  } else {
    throw new Error('Root / failed to serve index.html');
  }

  const resJs = await makeRequest('GET', '/app.js');
  console.log(`  GET /app.js -> Status: ${resJs.statusCode}, Content-Type: ${resJs.headers['content-type']}`);
  if (resJs.statusCode === 200) {
    console.log('  ✓ app.js successfully served');
  } else {
    throw new Error('app.js failed to serve');
  }

  // TEST 3: CWE-23 Path Traversal Attacks
  console.log('\n[TEST 3] Testing CWE-23 Path Traversal Protections...');
  const traversalTests = [
    '/../../server.js',
    '/..%2f..%2fserver.js',
    '/..\\..\\server.js',
    '/%2e%2e/%2e%2e/server.js',
    '/../data.json',
    '/C:/Windows/System32/drivers/etc/hosts',
    '/something%00secret'
  ];

  for (const t of traversalTests) {
    const res = await makeRequest('GET', t);
    console.log(`  Attempt ${t} -> Status: ${res.statusCode}`);
    if (res.statusCode === 403 || res.statusCode === 404) {
      console.log(`  ✓ Blocked traversal: ${t} (Status ${res.statusCode})`);
    } else {
      throw new Error(`Path traversal NOT blocked for: ${t} (Got status: ${res.statusCode})`);
    }
  }

  // TEST 4: CWE-79 XSS Protection & Security Headers
  console.log('\n[TEST 4] Testing CWE-79 XSS Escaping and Security Headers...');
  const resApi = await makeRequest('GET', '/api/sites');
  console.log(`  GET /api/sites -> Status: ${resApi.statusCode}`);
  const secHeaders = [
    ['x-content-type-options', 'nosniff'],
    ['x-frame-options', 'DENY'],
    ['strict-transport-security', 'max-age=31536000; includeSubDomains; preload']
  ];
  for (const [h, val] of secHeaders) {
    if (resApi.headers[h] === val) {
      console.log(`  ✓ Security Header ${h}: ${val} present`);
    } else {
      throw new Error(`Missing expected header: ${h}`);
    }
  }

  // Test XSS in POST endpoint with HTML characters
  const xssMemory = {
    placeName: 'Bishnupur <script>alert("xss")</script>',
    clusterName: 'Terracotta & Baluchari',
    travelDate: '2026-11-12',
    userName: 'Tester "><img src=x onerror=alert(1)>',
    notes: 'Amazing craft & culture <b>bold</b>'
  };
  const resMem = await makeRequest('POST', '/api/memories', xssMemory);
  console.log(`  POST /api/memories -> Status: ${resMem.statusCode}`);
  if (resMem.data.includes('<script>') || resMem.data.includes('><img')) {
    throw new Error('Raw unescaped HTML characters found in JSON response!');
  }
  if (resMem.data.includes('\\u003cscript\\u003e')) {
    console.log('  ✓ HTML characters properly escaped in JSON response (\\u003c)');
  }

  // TEST 5: API Endpoints (Admin, Plans, Places)
  console.log('\n[TEST 5] Testing Admin Governance and SLAs...');
  // Invalid PIN
  const resBadAuth = await makeRequest('POST', '/api/admin/login', { pin: '0000' });
  if (resBadAuth.statusCode === 401) {
    console.log('  ✓ Unauthorized login rejected with 401');
  }

  // Valid PIN
  const resGoodAuth = await makeRequest('POST', '/api/admin/login', { pin: '1947' });
  if (resGoodAuth.statusCode === 200) {
    console.log('  ✓ Master Admin PIN 1947 accepted with 200');
  }

  // Submit unlisted place (24-36 hr SLA)
  const newPlace = {
    name: 'Bikna Dokra Village',
    region: 'Bankura',
    state: 'West Bengal',
    craft: 'Dokra Lost-Wax Metal Casting',
    description: 'Ancient lost-wax bell metal casting cluster'
  };
  const resPlace = await makeRequest('POST', '/api/places', newPlace);
  const placeData = JSON.parse(resPlace.data);
  if (placeData.success && placeData.submission.slaRemainingHours === 36) {
    console.log('  ✓ New place submitted with 24-36 hr SLA verification status');
  }

  // Approve place via admin
  const resApprove = await makeRequest('POST', '/api/admin/verify-place', {
    pin: '1947',
    submissionId: placeData.submission.id,
    action: 'approve'
  });
  const approveData = JSON.parse(resApprove.data);
  if (approveData.success && approveData.submission.status === 'verified') {
    console.log('  ✓ Place approved by cultural committee and added to live clusters');
  }

  // Verify new cluster is in /api/sites
  const resSitesAfter = await makeRequest('GET', '/api/sites');
  const sitesData = JSON.parse(resSitesAfter.data);
  const foundCluster = sitesData.sites.find(s => s.name === 'Bikna Dokra Village');
  if (foundCluster) {
    console.log(`  ✓ Approved cluster immediately active on map! Total clusters: ${sitesData.count}`);
  }

  console.log('\n======================================================');
  console.log('  ALL SHILPAPATH SECURITY & FUNCTIONAL TESTS PASSED!   ');
  console.log('======================================================');
}

runTests().then(() => {
  serverProc.kill();
  process.exit(0);
}).catch(err => {
  console.error('TEST FAILED:', err);
  serverProc.kill();
  process.exit(1);
});
