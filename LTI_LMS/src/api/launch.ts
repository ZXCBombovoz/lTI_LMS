import { VercelRequest, VercelResponse } from '@vercel/node';
import * as jose from 'jose';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed. LTI Launch must be POST.');
  }

  try {
    const idToken = req.body.id_token;
    if (!idToken) {
      return res.status(400).send('Missing id_token in launch request');
    }

    // Decode the token without verification first to see what we have
    const decoded = jose.decodeJwt(idToken) as any;
    
    // In a real production app, you MUST verify the signature here
    // using the platform's public keys (LTI_PLATFORM_JWKS_ENDPOINT).
    // For this stage, we'll extract the data to show the user.

    const launchData = {
      name: decoded.name || decoded.given_name || 'Пользователь',
      email: decoded.email || 'no-email@mtuci.ru',
      roles: decoded['https://purl.imsglobal.org/spec/lti/claim/roles'] || [],
      course: decoded['https://purl.imsglobal.org/spec/lti/claim/context']?.title || 'Курс МТУСИ',
      context: decoded['https://purl.imsglobal.org/spec/lti/claim/context'] || {},
      raw: decoded
    };

    // Redirect to the frontend with the data
    const protocol = req.headers['x-forwarded-proto'] || 'https';
    const host = req.headers.host;
    const redirectUrl = `${protocol}://${host}?launch_data=${encodeURIComponent(JSON.stringify(launchData))}`;
    
    res.setHeader('Content-Type', 'text/html');
    return res.send(`
      <script>
        window.location.href = "${redirectUrl}";
      </script>
      <p>Redirecting to dashboard...</p>
    `);
  } catch (error: any) {
    console.error('Launch error:', error);
    return res.status(500).send(`Launch Error: ${error.message}`);
  }
}
