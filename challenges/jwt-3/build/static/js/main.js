
// Wait for DOM to be ready
document.addEventListener('DOMContentLoaded', function() {
    const apiPrefix = typeof API_PREFIX !== 'undefined' ? API_PREFIX : '/api/jwt-3';
    
    initNavigation();
    
    initLoginForm(apiPrefix);
    initUserPanel(apiPrefix);
    initAdminPanel(apiPrefix);
    initTokenManagement();
    initPublicKeyFetch(apiPrefix);
    
    updateTokenDisplay();
});

/**
 * Navigation handling
 */
function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('.section');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetSection = this.getAttribute('data-section');
            
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            
            sections.forEach(section => {
                if (section.id === targetSection) {
                    section.classList.add('active');
                } else {
                    section.classList.remove('active');
                }
            });
        });
    });
}

/**
 * Login form handling
 */
function initLoginForm(apiPrefix) {
    const loginForm = document.getElementById('login-form');
    const loginResult = document.getElementById('login-result');
    
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch(`${apiPrefix}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Store token
                    localStorage.setItem('jwt_token', data.token);
                    updateTokenDisplay();
                    
                    // Show success
                    showResult(loginResult, 'success', `
                        <strong>✅ Login Successful!</strong>
                        <p>Message: ${data.message}</p>
                    `);
                } else {
                    showResult(loginResult, 'error', `
                        <strong>❌ Login Failed</strong>
                        <p>${data.error}</p>
                    `);
                }
            } catch (error) {
                showResult(loginResult, 'error', `
                    <strong>❌ Request Failed</strong>
                    <p>${error.message}</p>
                `);
            }
        });
    }
}

/**
 * User panel handling
 */
function initUserPanel(apiPrefix) {
    const fetchMeBtn = document.getElementById('fetch-me');
    const userResult = document.getElementById('user-result');
    
    if (fetchMeBtn) {
        fetchMeBtn.addEventListener('click', async function() {
            const token = localStorage.getItem('jwt_token');
            
            if (!token) {
                showResult(userResult, 'error', `
                    <strong>⚠️ No Token</strong>
                    <p>Please login first to get a token.</p>
                `);
                return;
            }
            
            try {
                const response = await fetch(`${apiPrefix}/me`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showResult(userResult, 'success', `
                        <strong>✅ User Info Retrieved!</strong>
                        <p><strong>Username:</strong> ${data.username}</p>
                        <p><strong>Role:</strong> ${data.role}</p>
                        <p><strong>Message:</strong> ${data.message}</p>
                        <p class="flag">🚩 FLAG: ${data.flag}</p>
                    `);
                } else {
                    showResult(userResult, 'error', `
                        <strong>❌ Access Denied</strong>
                        <p>${data.error}</p>
                    `);
                }
            } catch (error) {
                showResult(userResult, 'error', `
                    <strong>❌ Request Failed</strong>
                    <p>${error.message}</p>
                `);
            }
        });
    }
}

/**
 * Admin panel handling
 */
function initAdminPanel(apiPrefix) {
    const fetchAdminBtn = document.getElementById('fetch-admin');
    const adminResult = document.getElementById('admin-result');
    
    if (fetchAdminBtn) {
        fetchAdminBtn.addEventListener('click', async function() {
            const token = localStorage.getItem('jwt_token');
            
            if (!token) {
                showResult(adminResult, 'error', `
                    <strong>⚠️ No Token</strong>
                    <p>Please login first to get a token.</p>
                `);
                return;
            }
            
            try {
                const response = await fetch(`${apiPrefix}/admin`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showResult(adminResult, 'success', `
                        <strong>🎉 Admin Access Granted!</strong>
                        <p><strong>Message:</strong> ${data.message}</p>
                        <p class="flag">🚩 FLAG: ${data.flag}</p>
                        <p><em>${data.secret}</em></p>
                    `);
                } else {
                    showResult(adminResult, 'error', `
                        <strong>❌ Access Denied</strong>
                        <p>${data.error}</p>
                        ${data.your_role ? `<p>Your current role: <strong>${data.your_role}</strong></p>` : ''}
                    `);
                }
            } catch (error) {
                showResult(adminResult, 'error', `
                    <strong>❌ Request Failed</strong>
                    <p>${error.message}</p>
                `);
            }
        });
    }
}

/**
 * Public key fetch handling
 */
function initPublicKeyFetch(apiPrefix) {
    const fetchPubkeyBtn = document.getElementById('fetch-pubkey');
    const pubkeyDisplay = document.getElementById('pubkey-display');
    
    if (fetchPubkeyBtn && pubkeyDisplay) {
        fetchPubkeyBtn.addEventListener('click', async function() {
            try {
                const response = await fetch(`${apiPrefix}/pubkey`);
                const pubkey = await response.text();
                pubkeyDisplay.textContent = pubkey;
            } catch (error) {
                pubkeyDisplay.textContent = `Error fetching public key: ${error.message}`;
            }
        });
    }
}

/**
 * Token management
 */
function initTokenManagement() {
    const clearTokenBtn = document.getElementById('clear-token');
    
    if (clearTokenBtn) {
        clearTokenBtn.addEventListener('click', function() {
            localStorage.removeItem('jwt_token');
            updateTokenDisplay();
        });
    }
}

/**
 * Update token display
 */
function updateTokenDisplay() {
    const tokenDisplay = document.getElementById('current-token');
    const token = localStorage.getItem('jwt_token');
    
    if (tokenDisplay) {
        if (token) {
            tokenDisplay.textContent = token;
        } else {
            tokenDisplay.textContent = 'No token stored';
        }
    }
}

/**
 * Show result in result div
 */
function showResult(element, type, content) {
    if (element) {
        element.className = `result show ${type}`;
        element.innerHTML = content;
    }
}
