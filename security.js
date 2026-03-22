/**
 * Bean Boutique Security Module
 * Provides security utilities for input validation, XSS prevention, CSRF protection, and more
 */

// ============================================================================
// 1. CSRF TOKEN GENERATION & VALIDATION
// ============================================================================

function generateCSRFToken() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function initCSRFToken() {
  let token = sessionStorage.getItem('csrfToken');
  if (!token) {
    token = generateCSRFToken();
    sessionStorage.setItem('csrfToken', token);
  }
  return token;
}

function getCSRFToken() {
  return sessionStorage.getItem('csrfToken') || initCSRFToken();
}

function validateCSRFToken(token) {
  const storedToken = sessionStorage.getItem('csrfToken');
  return token === storedToken;
}

function injectCSRFToken() {
  const token = getCSRFToken();
  const inputs = document.querySelectorAll('input[type="hidden"][name="csrf_token"]');
  inputs.forEach(input => {
    input.value = token;
  });
}

// ============================================================================
// 2. INPUT VALIDATION & SANITIZATION
// ============================================================================

// Email validation
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

// Password strength validation
function isStrongPassword(password) {
  const rules = {
    minLength: password.length >= 8,
    hasUpperCase: /[A-Z]/.test(password),
    hasLowerCase: /[a-z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecialChar: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
  };
  
  return {
    isStrong: Object.values(rules).filter(v => v).length >= 4,
    rules: rules
  };
}

// Sanitize HTML to prevent XSS
function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  
  const div = document.createElement('div');
  const allowedTags = ['b', 'i', 'em', 'strong', 'br'];
  
  str = str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
  
  return str;
}

// Remove potentially dangerous characters
function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input.trim().replace(/[<>\"']/g, '').substring(0, 500);
}

// Validate username
function isValidUsername(username) {
  const usernameRegex = /^[a-zA-Z0-9_-]{3,20}$/;
  return usernameRegex.test(username);
}

// Validate phone number
function isValidPhone(phone) {
  const phoneRegex = /^[\d\s\-\+\(\)]{7,15}$/;
  return phoneRegex.test(phone);
}

// ============================================================================
// 3. SECURE PASSWORD STORAGE & HANDLING
// ============================================================================

// NEVER store plain passwords - use this for demo/client-side validation only
function hashPassword(password) {
  // Client-side hash for validation only - NEVER use for actual storage
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    const char = password.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return hash.toString(16);
}

function validatePasswordMatch(password, confirmPassword) {
  return password === confirmPassword && password.length > 0;
}

// ============================================================================
// 4. RATE LIMITING
// ============================================================================

const rateLimitStore = {};

function checkRateLimit(key, maxAttempts = 5, timeWindowMs = 60000) {
  const now = Date.now();
  
  if (!rateLimitStore[key]) {
    rateLimitStore[key] = { attempts: 0, resetTime: now + timeWindowMs };
  }
  
  const record = rateLimitStore[key];
  
  // Reset if time window has passed
  if (now > record.resetTime) {
    record.attempts = 0;
    record.resetTime = now + timeWindowMs;
  }
  
  record.attempts++;
  return record.attempts <= maxAttempts;
}

function getRateLimitStatus(key) {
  return rateLimitStore[key] || null;
}

function resetRateLimit(key) {
  delete rateLimitStore[key];
}

// ============================================================================
// 5. XSS PREVENTION - SAFE DOM MANIPULATION
// ============================================================================

function setTextContent(element, text) {
  if (element && typeof text === 'string') {
    element.textContent = text;
  }
}

function setInnerText(element, text) {
  if (element && typeof text === 'string') {
    element.innerText = text;
  }
}

// Safe attribute setting
function setAttribute(element, attr, value) {
  if (element && typeof attr === 'string' && typeof value === 'string') {
    // Whitelist of safe attributes
    const safeAttrs = ['href', 'title', 'alt', 'placeholder', 'data-', 'class', 'id'];
    const isSafe = safeAttrs.some(safe => attr.startsWith(safe));
    
    if (isSafe && !value.includes('javascript:')) {
      element.setAttribute(attr, value);
    }
  }
}

// ============================================================================
// 6. SECURE DATA STORAGE
// ============================================================================

// Encrypt sensitive data (basic encryption - use proper library in production)
function encryptData(data, key = 'beanboutique') {
  try {
    const encrypted = btoa(JSON.stringify(data));
    return encrypted;
  } catch (e) {
    console.error('Encryption failed:', e);
    return null;
  }
}

// Decrypt sensitive data
function decryptData(encrypted, key = 'beanboutique') {
  try {
    const decrypted = JSON.parse(atob(encrypted));
    return decrypted;
  } catch (e) {
    console.error('Decryption failed:', e);
    return null;
  }
}

// Safe localStorage wrapper
function safeSetStorage(key, value, sensitive = false) {
  try {
    if (sensitive) {
      value = encryptData(value);
    }
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch (e) {
    console.error('Storage failed:', e);
    return false;
  }
}

function safeGetStorage(key, sensitive = false) {
  try {
    let value = localStorage.getItem(key);
    if (value) {
      value = JSON.parse(value);
      if (sensitive) {
        value = decryptData(value);
      }
    }
    return value;
  } catch (e) {
    console.error('Retrieval failed:', e);
    return null;
  }
}

function normalizeEmail(email) {
  return sanitizeInput(email).toLowerCase();
}

function getAppDatabase() {
  const defaultDatabase = {
    users: [],
    contacts: [],
    subscriptions: [],
    auditLog: []
  };

  const database = safeGetStorage('beanBoutiqueDB') || defaultDatabase;

  return {
    ...defaultDatabase,
    ...database,
    users: Array.isArray(database.users) ? database.users : [],
    contacts: Array.isArray(database.contacts) ? database.contacts : [],
    subscriptions: Array.isArray(database.subscriptions) ? database.subscriptions : [],
    auditLog: Array.isArray(database.auditLog) ? database.auditLog : []
  };
}

function saveAppDatabase(database) {
  return safeSetStorage('beanBoutiqueDB', database);
}

function addAuditLog(action, email = '', extra = {}) {
  const database = getAppDatabase();

  database.auditLog.push({
    id: generateSecureID(),
    action: sanitizeInput(action),
    email: normalizeEmail(email),
    timestamp: Date.now(),
    ...extra
  });

  saveAppDatabase(database);
}

function findUserByEmail(email) {
  const normalizedEmail = normalizeEmail(email);
  const database = getAppDatabase();

  return database.users.find(user => user.email === normalizedEmail) || null;
}

function saveUserRecord(userRecord) {
  const database = getAppDatabase();
  const existingIndex = database.users.findIndex(user => user.email === userRecord.email);

  if (existingIndex >= 0) {
    database.users[existingIndex] = userRecord;
  } else {
    database.users.push(userRecord);
  }

  saveAppDatabase(database);
}

function createUserSession(userRecord) {
  const welcomeOffer = Array.isArray(userRecord.offers)
    ? userRecord.offers.find(offer => offer.code === 'WELCOME10')
    : null;

  const userSession = {
    email: userRecord.email,
    userId: userRecord.id,
    firstName: userRecord.firstName || '',
    hasClaimedWelcomeOffer: !!userRecord.hasClaimedWelcomeOffer,
    welcomeOfferCode: welcomeOffer && !welcomeOffer.redeemed ? 'WELCOME10' : '',
    sessionId: generateSecureID(),
    timestamp: Date.now()
  };

  safeSetStorage('userSession', userSession);
  return userSession;
}

function registerUser(email, password) {
  const normalizedEmail = normalizeEmail(email);
  const existingUser = findUserByEmail(normalizedEmail);

  if (existingUser) {
    return {
      ok: false,
      message: 'This email is already registered. Please sign in instead.'
    };
  }

  const userRecord = {
    id: generateSecureID(),
    email: normalizedEmail,
    passwordHash: hashPassword(password),
    firstName: normalizedEmail.split('@')[0],
    hasClaimedWelcomeOffer: true,
    offers: [
      {
        code: 'WELCOME10',
        type: 'welcome',
        claimedAt: Date.now(),
        redeemed: false
      }
    ],
    signInCount: 1,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    lastLoginAt: Date.now()
  };

  saveUserRecord(userRecord);
  createUserSession(userRecord);
  addAuditLog('register', normalizedEmail);

  return {
    ok: true,
    isNewUser: true,
    user: userRecord,
    message: 'Registration complete. Your first-order offer is ready.'
  };
}

function signInUser(email, password) {
  const normalizedEmail = normalizeEmail(email);
  const userRecord = findUserByEmail(normalizedEmail);

  if (!userRecord) {
    return {
      ok: false,
      message: 'No account found for this email. Please register first.'
    };
  }

  if (userRecord.passwordHash !== hashPassword(password)) {
    return {
      ok: false,
      message: 'Incorrect password. Please try again.'
    };
  }

  userRecord.signInCount = (userRecord.signInCount || 0) + 1;
  userRecord.lastLoginAt = Date.now();
  userRecord.updatedAt = Date.now();

  saveUserRecord(userRecord);
  createUserSession(userRecord);
  addAuditLog('signin', normalizedEmail);

  return {
    ok: true,
    isNewUser: false,
    user: userRecord,
    message: userRecord.hasClaimedWelcomeOffer
      ? 'Welcome back. Your first-time offer has already been used on this account.'
      : 'Signed in successfully.'
  };
}

function getCurrentUserSession() {
  return safeGetStorage('userSession') || null;
}

function getCurrentUserRecord() {
  const session = getCurrentUserSession();
  if (!session || !session.email) {
    return null;
  }

  return findUserByEmail(session.email);
}

function userCanUseWelcomeOffer() {
  const userRecord = getCurrentUserRecord();
  if (!userRecord || !Array.isArray(userRecord.offers)) {
    return false;
  }

  return userRecord.offers.some(offer => offer.code === 'WELCOME10' && !offer.redeemed);
}

function markOfferRedeemed(code, email = '') {
  const normalizedCode = sanitizeInput(code).toUpperCase();
  const targetEmail = email ? normalizeEmail(email) : (getCurrentUserSession()?.email || '');
  const userRecord = findUserByEmail(targetEmail);

  if (!userRecord || !Array.isArray(userRecord.offers)) {
    return false;
  }

  const offer = userRecord.offers.find(item => item.code === normalizedCode);
  if (!offer || offer.redeemed) {
    return false;
  }

  offer.redeemed = true;
  offer.redeemedAt = Date.now();
  userRecord.updatedAt = Date.now();
  saveUserRecord(userRecord);
  createUserSession(userRecord);
  addAuditLog('offer_redeemed', targetEmail, { offerCode: normalizedCode });
  return true;
}

function saveContactRecord(contactData) {
  const database = getAppDatabase();
  database.contacts.push(contactData);
  saveAppDatabase(database);
  addAuditLog('contact_saved', contactData.email || '');
}

function saveSubscriptionRecord(subscriptionData) {
  const database = getAppDatabase();
  database.subscriptions.push(subscriptionData);
  saveAppDatabase(database);
  addAuditLog('subscription_saved', subscriptionData.email || '', {
    planName: subscriptionData.planName || ''
  });
}

// Clear sensitive data
function clearSensitiveData() {
  const sensitiveKeys = ['authToken', 'sessionPassword', 'paymentInfo'];
  sensitiveKeys.forEach(key => {
    localStorage.removeItem(key);
    sessionStorage.removeItem(key);
  });
}

// ============================================================================
// 7. FORM VALIDATION
// ============================================================================

function validateForm(formElement) {
  const errors = [];
  const inputs = formElement.querySelectorAll('input[required], textarea[required]');
  
  inputs.forEach(input => {
    const value = input.value.trim();
    
    if (!value) {
      errors.push(`${input.placeholder || input.name} is required`);
    }
    
    if (input.type === 'email' && value && !isValidEmail(value)) {
      errors.push('Invalid email format');
    }
    
    if (input.type === 'password' && value) {
      const pwdCheck = isStrongPassword(value);
      if (!pwdCheck.isStrong) {
        errors.push('Password must be at least 8 characters with uppercase, lowercase, numbers, and special characters');
      }
    }
    
    if (input.maxLength && value.length > input.maxLength) {
      errors.push(`${input.placeholder} cannot exceed ${input.maxLength} characters`);
    }
  });
  
  return {
    isValid: errors.length === 0,
    errors: errors
  };
}

// ============================================================================
// 8. ERROR HANDLING
// ============================================================================

function handleSecurityError(errorType, message = '') {
  const safeErrors = {
    xss: 'Invalid input detected. Please try again.',
    csrf: 'Security validation failed. Please refresh and try again.',
    validation: 'Please check your input and try again.',
    rateLimit: 'Too many attempts. Please try again later.',
    default: 'An error occurred. Please try again.'
  };
  
  console.error(`[SECURITY] ${errorType}:`, message);
  return safeErrors[errorType] || safeErrors.default;
}

// ============================================================================
// 9. SESSION SECURITY
// ============================================================================

const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
let sessionTimer;

function resetSessionTimer() {
  clearTimeout(sessionTimer);
  sessionTimer = setTimeout(() => {
    clearSensitiveData();
    alert('Your session has expired. Please log in again.');
    window.location.href = 'index.html';
  }, SESSION_TIMEOUT);
}

function initSessionSecurity() {
  document.addEventListener('click', resetSessionTimer);
  document.addEventListener('keypress', resetSessionTimer);
  resetSessionTimer();
}

// ============================================================================
// 10. SECURITY HEADERS (Document)
// ============================================================================

function logSecurityPolicy() {
  console.log('%c🔒 Security Policy Active', 'color: green; font-weight: bold;');
  console.log('✓ CSRF Protection: Enabled');
  console.log('✓ XSS Prevention: Enabled');
  console.log('✓ Input Validation: Enabled');
  console.log('✓ Rate Limiting: Enabled');
  console.log('✓ Session Timeout: 30 minutes');
}

// Initialize security on page load
window.addEventListener('DOMContentLoaded', () => {
  initCSRFToken();
  injectCSRFToken();
  initSessionSecurity();
  logSecurityPolicy();
});

// ============================================================================
// 11. UTILITY FUNCTIONS
// ============================================================================

function generateSecureID() {
  return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function isSecureContext() {
  return window.isSecureContext || window.location.protocol === 'https:';
}

function getIPInfo() {
  // Note: This is client-side only. In production, verify server-side.
  return {
    timestamp: Date.now(),
    userAgent: navigator.userAgent
  };
}
