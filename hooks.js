/**
 * n8n External Hooks for OIDC Authentication
 *
 * This file implements OIDC authentication support for n8n using only built-in Node.js modules.
 * It provides:
 * - OIDC discovery endpoint support
 * - Authorization code flow
 * - User provisioning (JIT - Just In Time)
 * - Native n8n frontend SSO integration & fallback DOM injector
 *
 * Environment Variables Required:
 * - OIDC_ISSUER_URL: The OIDC provider's issuer URL (e.g., https://auth.example.com)
 * - OIDC_CLIENT_ID: OAuth2 client ID
 * - OIDC_CLIENT_SECRET: OAuth2 client secret
 * - OIDC_REDIRECT_URI: The callback URL (e.g., https://n8n.example.com/auth/oidc/callback)
 *
 * Optional:
 * - OIDC_SCOPES: Space-separated list of scopes (default: "openid email profile")
 */

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { URL, URLSearchParams } = require('url');
const { createRequire } = require('module');

// Helper to resolve n8n internal modules across different n8n versions & layouts
function resolveN8nModule(modulePath) {
  try {
    return require(modulePath);
  } catch (e) {}

  const roots = [
    '/usr/local/lib/node_modules/n8n/dist/commands/start.js',
    '/usr/local/lib/node_modules/n8n/package.json',
  ];
  for (const root of roots) {
    try {
      const n8nRequire = createRequire(root);
      return n8nRequire(modulePath);
    } catch (e) {}
  }
  return null;
}

function getN8nContainer() {
  const candidates = [
    '@n8n/di',
    '/usr/local/lib/node_modules/n8n/node_modules/@n8n/di',
    '/usr/local/lib/node_modules/@n8n/di',
  ];
  for (const c of candidates) {
    const mod = resolveN8nModule(c);
    if (mod && mod.Container) return mod.Container;
  }
  return null;
}

function getN8nJwtService() {
  const candidates = [
    '@n8n/backend-services',
    '/usr/local/lib/node_modules/n8n/node_modules/@n8n/backend-services',
    '/usr/local/lib/node_modules/@n8n/backend-services',
    '/usr/local/lib/node_modules/n8n/dist/services/jwt.service.js',
    '/usr/local/lib/node_modules/n8n/dist/auth/jwt.service.js',
  ];
  for (const c of candidates) {
    const mod = resolveN8nModule(c);
    if (mod) {
      if (mod.JwtService) return mod.JwtService;
      if (typeof mod === 'function' && mod.name === 'JwtService') return mod;
    }
  }
  return null;
}

function getN8nAuthService() {
  const candidates = [
    '/usr/local/lib/node_modules/n8n/dist/auth/auth.service.js',
    'n8n/dist/auth/auth.service.js',
  ];
  for (const c of candidates) {
    const mod = resolveN8nModule(c);
    if (mod && mod.AuthService) return mod.AuthService;
  }
  return null;
}

function getN8nAuthJwtHelper() {
  const candidates = [
    '/usr/local/lib/node_modules/n8n/dist/auth/jwt.js',
    'n8n/dist/auth/jwt.js',
  ];
  for (const c of candidates) {
    const mod = resolveN8nModule(c);
    if (mod && (mod.issueCookie || mod.issueJWT)) return mod;
  }
  return null;
}

// Configuration from environment
const config = {
  issuerUrl: process.env.OIDC_ISSUER_URL,
  clientId: process.env.OIDC_CLIENT_ID,
  clientSecret: process.env.OIDC_CLIENT_SECRET,
  redirectUri: process.env.OIDC_REDIRECT_URI,
  scopes: process.env.OIDC_SCOPES || 'openid email profile',
};

// Validate configuration
function validateConfig() {
  const missing = [];
  if (!config.issuerUrl) missing.push('OIDC_ISSUER_URL');
  if (!config.clientId) missing.push('OIDC_CLIENT_ID');
  if (!config.clientSecret) missing.push('OIDC_CLIENT_SECRET');
  if (!config.redirectUri) missing.push('OIDC_REDIRECT_URI');
  return missing;
}

// Cache for OIDC discovery document
let discoveryCache = null;
let discoveryCacheTime = 0;
const DISCOVERY_CACHE_TTL = 3600000; // 1 hour

/**
 * Make an HTTP/HTTPS request
 * @param {string} url - The URL to request
 * @param {object} options - Request options
 * @returns {Promise<{statusCode: number, headers: object, body: string}>}
 */
function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const protocol = parsedUrl.protocol === 'https:' ? https : http;

    const headers = Object.assign({}, options.headers || {});
    if (options.body && !headers['Content-Length'] && !headers['content-length']) {
      headers['Content-Length'] = Buffer.byteLength(options.body);
    }

    const reqOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || 'GET',
      headers,
    };

    const req = protocol.request(reqOptions, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body,
        });
      });
    });

    req.on('error', reject);

    if (options.body) {
      req.write(options.body);
    }

    req.end();
  });
}

/**
 * Fetch OIDC discovery document
 * @returns {Promise<object>}
 */
async function fetchDiscoveryDocument() {
  const now = Date.now();
  if (discoveryCache && now - discoveryCacheTime < DISCOVERY_CACHE_TTL) {
    return discoveryCache;
  }

  const discoveryUrl = config.issuerUrl.replace(/\/$/, '') + '/.well-known/openid-configuration';
  const response = await makeRequest(discoveryUrl);

  if (response.statusCode !== 200) {
    throw new Error(`Failed to fetch OIDC discovery document: ${response.statusCode}`);
  }

  discoveryCache = JSON.parse(response.body);
  discoveryCacheTime = now;
  return discoveryCache;
}

/**
 * Generate a random string for state/nonce
 * @param {number} length
 * @returns {string}
 */
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Base64URL encode
 * @param {Buffer|string} input
 * @returns {string}
 */
function base64UrlEncode(input) {
  const base64 = Buffer.isBuffer(input) ? input.toString('base64') : Buffer.from(input).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Base64URL decode
 * @param {string} input
 * @returns {Buffer}
 */
function base64UrlDecode(input) {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Decode JWT without verification (for extracting claims)
 * @param {string} token
 * @returns {object}
 */
function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
  return payload;
}

/**
 * Exchange authorization code for tokens
 * @param {string} code
 * @param {object} discovery
 * @returns {Promise<object>}
 */
async function exchangeCodeForTokens(code, discovery) {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    client_secret: config.clientSecret,
  });

  const bodyString = params.toString();
  const response = await makeRequest(discovery.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(bodyString),
    },
    body: bodyString,
  });

  if (response.statusCode !== 200) {
    console.error('[OIDC Hook] Token exchange failed:', response.statusCode, response.body);
    throw new Error(`Token exchange failed: ${response.statusCode}`);
  }

  return JSON.parse(response.body);
}

/**
 * Fetch user info from OIDC provider
 * @param {string} accessToken
 * @param {object} discovery
 * @returns {Promise<object>}
 */
async function fetchUserInfo(accessToken, discovery) {
  const response = await makeRequest(discovery.userinfo_endpoint, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (response.statusCode !== 200) {
    console.error('[OIDC Hook] UserInfo fetch failed:', response.statusCode, response.body);
    throw new Error(`UserInfo fetch failed: ${response.statusCode}`);
  }

  return JSON.parse(response.body);
}

/**
 * Create a signed JWT for state/nonce storage
 * We use the JWT service from n8n when available, but for cookies we just use HMAC
 * @param {object} payload
 * @param {string} secret
 * @param {number} expiresInSeconds
 * @returns {string}
 */
function createSignedCookie(payload, secret, expiresInSeconds = 900) {
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const data = JSON.stringify({ ...payload, exp });
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(data);
  const signature = hmac.digest('hex');
  return base64UrlEncode(data) + '.' + signature;
}

/**
 * Verify and decode a signed cookie
 * @param {string} cookie
 * @param {string} secret
 * @returns {object|null}
 */
function verifySignedCookie(cookie, secret) {
  try {
    const [dataB64, signature] = cookie.split('.');
    const data = base64UrlDecode(dataB64).toString('utf8');

    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(data);
    const expectedSignature = hmac.digest('hex');

    if (signature !== expectedSignature) {
      return null;
    }

    const payload = JSON.parse(data);
    if (payload.exp && payload.exp < Date.now() / 1000) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * Get or create the cookie signing secret
 * We derive it from the n8n encryption key if available
 * @param {object} context
 * @returns {string}
 */
function getCookieSecret(context) {
  // Use a combination of environment variables to create a stable secret
  const baseKey = process.env.N8N_ENCRYPTION_KEY || process.env.OIDC_CLIENT_SECRET || 'n8n-oidc-hook-secret';
  const hash = crypto.createHash('sha256').update(baseKey + '-oidc-state').digest('hex');
  return hash;
}

/**
 * Create user hash for JWT (mimics n8n's AuthService.createJWTHash)
 * @param {object} user
 * @returns {string}
 */
function createUserHash(user) {
  const payload = [user.email, user.password || ''];
  if (user.mfaEnabled && user.mfaSecret) {
    payload.push(user.mfaSecret.substring(0, 3));
  }
  return crypto.createHash('sha256').update(payload.join(':')).digest('base64').substring(0, 10);
}

/**
 * Create the n8n auth cookie using n8n's JwtService
 * @param {object} user
 * @param {object} jwtService - n8n's JwtService instance
 * @returns {string}
 */
function createAuthToken(user, jwtService) {
  // n8n's JWT contains: { id, hash, browserId?, usedMfa? }
  const payload = {
    id: user.id,
    hash: createUserHash(user),
    usedMfa: false,
  };

  try {
    return jwtService.sign(payload, { expiresIn: '7d' });
  } catch (err) {
    try {
      return jwtService.sign(payload, 'auth', { expiresIn: '7d' });
    } catch (e1) {
      try {
        return jwtService.sign(payload, { expiresIn: '7d', purpose: 'auth' });
      } catch (e2) {
        throw err;
      }
    }
  }
}

/**
 * Check if email is valid
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Export the hooks
module.exports = {
  n8n: {
    /**
     * Called when n8n is ready
     * We use this to register custom routes for OIDC and enable native SSO UI
     */
    ready: [
      async function (server, n8nConfig) {
        const missing = validateConfig();
        if (missing.length > 0) {
          console.warn(`[OIDC Hook] Missing configuration: ${missing.join(', ')}. OIDC disabled.`);
          return;
        }

        console.log('[OIDC Hook] Initializing OIDC authentication...');

        // Configure frontendService to report OIDC is licensed & active
        if (server && server.frontendService) {
          console.log('[OIDC Hook] Patching frontendService to enable native SSO UI');

          if (server.frontendService.licenseState) {
            server.frontendService.licenseState.isOidcLicensed = () => true;
          }

          const origGetPublicSettings = server.frontendService.getPublicSettings.bind(server.frontendService);
          server.frontendService.getPublicSettings = async function (includeMfa) {
            const settings = await origGetPublicSettings(includeMfa);
            if (settings) {
              if (settings.userManagement) {
                settings.userManagement.authenticationMethod = 'oidc';
              }
              if (settings.enterprise) {
                settings.enterprise.oidc = true;
              }
              if (settings.sso) {
                settings.sso.oidc = settings.sso.oidc || {};
                settings.sso.oidc.loginEnabled = true;
                settings.sso.oidc.loginUrl = '/auth/oidc/login';
              }
            }
            return settings;
          };

          const origGetSettings = server.frontendService.getSettings.bind(server.frontendService);
          server.frontendService.getSettings = async function () {
            const settings = await origGetSettings();
            if (settings) {
              if (settings.userManagement) {
                settings.userManagement.authenticationMethod = 'oidc';
              }
              if (settings.enterprise) {
                settings.enterprise.oidc = true;
              }
              if (settings.sso) {
                settings.sso.oidc = settings.sso.oidc || {};
                settings.sso.oidc.loginEnabled = true;
                settings.sso.oidc.loginUrl = '/auth/oidc/login';
              }
            }
            return settings;
          };
        }

        // Setup authentication helper references safely (pre-load or lazy fallback)
        let Container = null;
        let jwtService = null;
        try {
          Container = getN8nContainer();
          const JwtServiceClass = getN8nJwtService();
          if (Container && JwtServiceClass) {
            jwtService = Container.get(JwtServiceClass);
          }
        } catch (e) {
          console.warn('[OIDC Hook] Warning: could not preload JwtService at startup:', e.message);
        }

        const { app } = server;
        const cookieSecret = getCookieSecret();

        // Cookie settings
        const cookieOptions = {
          path: '/',
          httpOnly: true,
          secure: process.env.N8N_PROTOCOL === 'https',
          sameSite: 'lax',
          maxAge: 15 * 60 * 1000, // 15 minutes
        };

        const authCookieOptions = {
          path: '/',
          httpOnly: true,
          secure: process.env.N8N_PROTOCOL === 'https',
          sameSite: 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        };

        /**
         * OIDC Login endpoint - redirects to the OIDC provider
         */
        app.get('/auth/oidc/login', async (req, res) => {
          try {
            const discovery = await fetchDiscoveryDocument();

            const state = generateRandomString();
            const nonce = generateRandomString();

            // Store state and nonce in signed cookies
            const stateCookie = createSignedCookie({ state }, cookieSecret);
            const nonceCookie = createSignedCookie({ nonce }, cookieSecret);

            res.cookie('n8n-oidc-state', stateCookie, cookieOptions);
            res.cookie('n8n-oidc-nonce', nonceCookie, cookieOptions);

            // Build authorization URL
            const authUrl = new URL(discovery.authorization_endpoint);
            authUrl.searchParams.set('client_id', config.clientId);
            authUrl.searchParams.set('redirect_uri', config.redirectUri);
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('scope', config.scopes);
            authUrl.searchParams.set('state', state);
            authUrl.searchParams.set('nonce', nonce);

            res.redirect(authUrl.toString());
          } catch (error) {
            console.error('[OIDC Hook] Login error:', error);
            res.status(500).send('OIDC configuration error. Please check the logs.');
          }
        });

        /**
         * OIDC Callback endpoint - handles the authorization code
         */
        app.get('/auth/oidc/callback', async (req, res) => {
          try {
            const { code, state, error, error_description } = req.query;

            // Handle OIDC errors
            if (error) {
              console.error('[OIDC Hook] OIDC error from provider:', error, error_description);
              return res.redirect('/signin?error=' + encodeURIComponent(error_description || error));
            }

            if (!code || !state) {
              return res.redirect('/signin?error=' + encodeURIComponent('Missing authorization code or state'));
            }

            // Verify state
            const stateCookie = req.cookies['n8n-oidc-state'];
            const nonceCookie = req.cookies['n8n-oidc-nonce'];

            if (!stateCookie || !nonceCookie) {
              return res.redirect('/signin?error=' + encodeURIComponent('Missing state cookies - session expired'));
            }

            const statePayload = verifySignedCookie(stateCookie, cookieSecret);
            const noncePayload = verifySignedCookie(nonceCookie, cookieSecret);

            if (!statePayload || statePayload.state !== state) {
              return res.redirect('/signin?error=' + encodeURIComponent('Invalid state - possible CSRF attack'));
            }

            // Clear state cookies
            res.clearCookie('n8n-oidc-state', cookieOptions);
            res.clearCookie('n8n-oidc-nonce', cookieOptions);

            // Exchange code for tokens
            const discovery = await fetchDiscoveryDocument();
            const tokens = await exchangeCodeForTokens(code, discovery);

            // Verify nonce in ID token if present
            if (tokens.id_token) {
              const idTokenClaims = decodeJwt(tokens.id_token);
              if (noncePayload && idTokenClaims.nonce !== noncePayload.nonce) {
                return res.redirect('/signin?error=' + encodeURIComponent('Invalid nonce - possible replay attack'));
              }
            }

            // Get user info
            let userInfo;
            try {
              userInfo = await fetchUserInfo(tokens.access_token, discovery);
            } catch (e) {
              // Fall back to ID token claims if userinfo endpoint fails
              if (tokens.id_token) {
                userInfo = decodeJwt(tokens.id_token);
              } else {
                throw e;
              }
            }

            // Validate we have an email
            if (!userInfo.email || !isValidEmail(userInfo.email)) {
              return res.redirect('/signin?error=' + encodeURIComponent('No valid email in OIDC response'));
            }

            const email = userInfo.email.trim().toLowerCase();

            // Find or create user in n8n database
            const { User } = this.dbCollections;

            // Try to find existing user by email
            let user = await User.findOne({
              where: { email },
              relations: ['role'],
            });

            if (!user) {
              // Check if this is the first user (should be owner)
              const userCount = await User.count();

              const userData = {
                email,
                firstName: userInfo.given_name || userInfo.name?.split(' ')[0] || 'User',
                lastName: userInfo.family_name || userInfo.name?.split(' ').slice(1).join(' ') || '',
                password: crypto.randomBytes(32).toString('hex'), // Random password, can't be used
                role: { slug: userCount === 0 ? 'global:owner' : 'global:member' },
              };

              // Use createUserWithProject to create both user and personal project
              const result = await User.createUserWithProject(userData);
              user = result.user;

              console.log(`[OIDC Hook] Created ${userCount === 0 ? 'owner' : 'member'} user with personal project: ${email}`);
            }

            if (!user) {
              return res.redirect('/signin?error=' + encodeURIComponent('Failed to create or find user'));
            }

            // Create auth token / cookie using n8n's AuthService, JwtService, or JWT helper
            let authToken = null;
            let cookieIssued = false;

            // Strategy 1: AuthService from DI Container
            try {
              if (!Container) Container = getN8nContainer();
              const AuthServiceClass = getN8nAuthService();
              if (Container && AuthServiceClass) {
                const authService = Container.get(AuthServiceClass);
                if (authService) {
                  if (typeof authService.issueCookie === 'function') {
                    authService.issueCookie(res, user);
                    cookieIssued = true;
                  } else if (typeof authService.issueJWT === 'function') {
                    authToken = authService.issueJWT(user, false, req.browserId);
                  }
                }
              }
            } catch (authErr) {
              console.warn('[OIDC Hook] AuthService issuance failed:', authErr.message);
            }

            // Strategy 2: auth/jwt helper (issueCookie)
            if (!cookieIssued && !authToken) {
              try {
                const jwtHelper = getN8nAuthJwtHelper();
                if (jwtHelper) {
                  if (typeof jwtHelper.issueCookie === 'function') {
                    jwtHelper.issueCookie(res, user);
                    cookieIssued = true;
                  } else if (typeof jwtHelper.issueJWT === 'function') {
                    authToken = jwtHelper.issueJWT(user, false, req.browserId);
                  }
                }
              } catch (jwtHelperErr) {
                console.warn('[OIDC Hook] auth/jwt helper failed:', jwtHelperErr.message);
              }
            }

            // Strategy 3: JwtService from Container
            if (!cookieIssued && !authToken) {
              try {
                if (!jwtService) {
                  if (!Container) Container = getN8nContainer();
                  const JwtServiceClass = getN8nJwtService();
                  if (Container && JwtServiceClass) {
                    jwtService = Container.get(JwtServiceClass);
                  }
                }
                if (jwtService) {
                  authToken = createAuthToken(user, jwtService);
                }
              } catch (jwtErr) {
                console.warn('[OIDC Hook] JwtService creation failed:', jwtErr.message);
              }
            }

            // If cookie was not directly set by issueCookie, set it now
            if (!cookieIssued) {
              if (!authToken) {
                throw new Error('Could not generate n8n session token (all authentication providers failed)');
              }
              res.cookie('n8n-auth', authToken, authCookieOptions);
            }

            console.log(`[OIDC Hook] Successfully authenticated ${user.email} (${user.id}), redirecting to /`);

            // Redirect to home
            res.redirect('/');
          } catch (error) {
            console.error('[OIDC Hook] Callback error:', error);
            res.redirect('/signin?error=' + encodeURIComponent('Authentication failed: ' + error.message));
          }
        });

        /**
         * Serve the frontend customization script
         * This script acts as a robust fallback to ensure the SSO button is displayed
         *
         * NOTE: The route must be under /assets/ or another non-UI route prefix
         * to avoid being intercepted by n8n's history API handler which would
         * serve index.html instead of our JavaScript file.
         */
        app.get('/assets/oidc-frontend-hook.js', (req, res) => {
          // Use res.type() for proper MIME type handling with nosniff
          res.type('text/javascript; charset=utf-8');
          res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
          res.send(getFrontendScript());
        });

        console.log('[OIDC Hook] OIDC routes registered:');
        console.log('  - GET /auth/oidc/login');
        console.log('  - GET /auth/oidc/callback');
        console.log('  - GET /assets/oidc-frontend-hook.js');
      },
    ],
  },

  frontend: {
    /**
     * Modify frontend settings to configure SSO display
     */
    settings: [
      async function (frontendSettings) {
        const missing = validateConfig();
        if (missing.length > 0) {
          return; // OIDC not configured, don't modify settings
        }

        // Enable OIDC login button by setting these properties
        frontendSettings.sso = frontendSettings.sso || {};
        frontendSettings.sso.oidc = {
          loginEnabled: true,
          loginUrl: '/auth/oidc/login',
          callbackUrl: config.redirectUri,
        };

        // Set authentication method to OIDC so the frontend knows SSO is primary
        frontendSettings.userManagement = frontendSettings.userManagement || {};
        frontendSettings.userManagement.authenticationMethod = 'oidc';

        // Enable enterprise OIDC feature flag so the SSO button shows
        frontendSettings.enterprise = frontendSettings.enterprise || {};
        frontendSettings.enterprise.oidc = true;

        console.log('[OIDC Hook] Frontend settings configured for OIDC');
      },
    ],
  },
};

/**
 * Generate the frontend customization script
 * This script runs in the browser and provides a robust fallback for the SSO button
 */
function getFrontendScript() {
  return `
/**
 * n8n OIDC Frontend Customization
 *
 * This script ensures the SSO button is visible.
 * Primary mechanism: Native n8n SSO UI enabled via server.frontendService patch.
 * Fallback mechanism: DOM injection if native SSO UI is not rendered.
 * To access the normal login form, add ?showLogin=true to the URL.
 */
(function() {
	'use strict';

	function shouldShowNormalLogin() {
		return new URLSearchParams(window.location.search).get('showLogin') === 'true';
	}

	function isSigninPage() {
		return window.location.pathname.startsWith('/signin') ||
			window.location.pathname.startsWith('/login') ||
			!!document.querySelector('[data-test-id="form-submit-button"]') ||
			!!document.querySelector('[data-test-id="signin-form"]');
	}

	function displayError(container) {
		var error = new URLSearchParams(window.location.search).get('error');
		if (!error || !container || container.querySelector('#oidc-error')) return;

		var errorDiv = document.createElement('div');
		errorDiv.id = 'oidc-error';
		errorDiv.style.cssText = 'background: var(--color-danger-tint-1, #fee); border: 1px solid var(--color-danger, #fcc); color: var(--color-danger, #c00); padding: 12px; border-radius: 4px; margin: 16px 0;';
		errorDiv.textContent = decodeURIComponent(error);

		var heading = container.querySelector('div[class*="_heading_"], div[class*="heading"], h1, h2');
		if (heading) heading.after(errorDiv);
		else container.prepend(errorDiv);
	}

	function injectSsoButton() {
		if (shouldShowNormalLogin()) return;
		if (document.querySelector('[data-test-id="sso-login-button"]') || document.querySelector('#oidc-sso-button')) return;

		var submitBtn = document.querySelector('[data-test-id="form-submit-button"]');
		var form = document.querySelector('[data-test-id="auth-form"]') ||
			(submitBtn && (submitBtn.closest('.n8n-form-box') || submitBtn.closest('div[class*="container"]') || submitBtn.closest('form'))) ||
			document.querySelector('[data-test-id="signin-form"]');
		if (!form) return;

		var buttonClasses = submitBtn ? submitBtn.className : '';

		form.querySelectorAll('div[class*="_inputsContainer_"], div[class*="_buttonsContainer_"], div[class*="_actionContainer_"], div[class*="inputsContainer"], div[class*="buttonsContainer"], div[class*="actionContainer"]')
			.forEach(function(el) { el.style.display = 'none'; });

		var ssoContainer = document.createElement('div');
		ssoContainer.id = 'oidc-sso-container';
		ssoContainer.style.cssText = 'text-align: center; margin-top: 16px;';

		var button = document.createElement('button');
		button.id = 'oidc-sso-button';
		button.type = 'button';
		button.textContent = 'Sign in with SSO';
		button.onclick = function() { window.location.href = '/auth/oidc/login'; };

		if (buttonClasses) {
			button.className = buttonClasses;
			button.style.width = '100%';
		} else {
			button.style.cssText = 'width: 100%; padding: 12px 24px; font-size: 14px; font-weight: 600; color: white; background: var(--color-primary, #ea4b30); border: none; border-radius: 4px; cursor: pointer;';
		}

		var adminLink = document.createElement('p');
		adminLink.style.cssText = 'margin-top: 16px; font-size: 12px; color: var(--color-text-light, #666);';
		adminLink.innerHTML = 'Admin? <a href="?showLogin=true" style="color: var(--color-primary, #ea4b30);">Sign in with email</a>';

		ssoContainer.appendChild(button);
		ssoContainer.appendChild(adminLink);

		var heading = form.querySelector('div[class*="_heading_"], div[class*="heading"], h1, h2');
		if (heading) heading.after(ssoContainer);
		else form.prepend(ssoContainer);

		displayError(form);
	}

	function observeAndInject() {
		if (shouldShowNormalLogin()) return;
		injectSsoButton();

		if (!window.__oidcObserverAttached) {
			window.__oidcObserverAttached = true;
			var observer = new MutationObserver(function() {
				if (!shouldShowNormalLogin() && isSigninPage()) {
					injectSsoButton();
				}
			});
			observer.observe(document.documentElement || document.body, { childList: true, subtree: true });
		}
	}

	function handleNavigation() {
		var origPush = history.pushState;
		var origReplace = history.replaceState;

		history.pushState = function() {
			origPush.apply(this, arguments);
			setTimeout(observeAndInject, 50);
			setTimeout(observeAndInject, 200);
			setTimeout(observeAndInject, 500);
		};

		history.replaceState = function() {
			origReplace.apply(this, arguments);
			setTimeout(observeAndInject, 50);
			setTimeout(observeAndInject, 200);
			setTimeout(observeAndInject, 500);
		};

		window.addEventListener('popstate', function() {
			setTimeout(observeAndInject, 50);
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', function() {
			observeAndInject();
			handleNavigation();
		});
	} else {
		observeAndInject();
		handleNavigation();
	}

	setTimeout(observeAndInject, 100);
	setTimeout(observeAndInject, 500);
	setTimeout(observeAndInject, 1500);

	console.log('[OIDC Hook] Frontend customization loaded');
})();
`;
}
