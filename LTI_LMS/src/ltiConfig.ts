export const LTI_CONFIG = {
  // These should be updated based on Moodle's "Tool Configuration"
  clientId: process.env.LTI_CLIENT_ID || 'client_id_from_moodle',
  platformOidcAuthEndpoint: process.env.LTI_OIDC_AUTH_ENDPOINT || 'https://your-moodle.com/mod/lti/auth.php',
  platformJwksEndpoint: process.env.LTI_PLATFORM_JWKS_ENDPOINT || 'https://your-moodle.com/mod/lti/certs.php',
  platformIssuer: process.env.LTI_ISSUER || 'https://your-moodle.com',
  
  // The tool's own information
  toolUrl: process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:5173',
  toolRedirectUri: process.env.VERCEL_URL 
    ? `https://${process.env.VERCEL_URL}/api/launch` 
    : 'http://localhost:5173/api/launch',
  toolJwkUrl: process.env.VERCEL_URL
    ? `https://${process.env.VERCEL_URL}/api/jwks`
    : 'http://localhost:5173/api/jwks',
};
