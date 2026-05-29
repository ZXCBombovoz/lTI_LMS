
// Упрощенная конфигурация для Vercel
export function getAppUrl() {
  return process.env.VITE_APP_URL || 'https://dip2-6bycqsvrg-ewf234112344w-1136s-projects.vercel.app';
}

export function getLtiConfig() {
  return {
    issuer: process.env.LTI_ISSUER || '',
    clientId: process.env.LTI_CLIENT_ID || 'ItVsNxbE8B8vyOh',
    platformJwksEndpoint: process.env.LTI_PLATFORM_JWKS_ENDPOINT || '',
    oidcAuthEndpoint: process.env.LTI_OIDC_AUTH_ENDPOINT || '',
    privateKey: process.env.LTI_PRIVATE_KEY || '',
  };
}
