import { VercelRequest, VercelResponse } from '@vercel/node';
import * as jose from 'jose';

export default async function handler(_: VercelRequest, res: VercelResponse) {
  try {
    const privateKeyRaw = process.env.LTI_PRIVATE_KEY;

    if (!privateKeyRaw) {
      return res.status(200).json({ keys: [] });
    }

    // Clean the key: replace escaped newlines and ensure proper format
    const privateKeyStr = privateKeyRaw.replace(/\\n/g, '\n').trim();

    try {
      // Import the private key to derive the public key
      // We MUST set extractable: true to be able to export it later
      const privateKey = await jose.importPKCS8(privateKeyStr, 'RS256', { extractable: true });
      
      // Export as JWK (public part only)
      const jwk = await jose.exportJWK(privateKey);
      
      // Add required LTI 1.3 fields
      const publicJwk = {
        ...jwk,
        kid: 'lti-key-1',
        use: 'sig',
        alg: 'RS256',
      };

      return res.status(200).json({
        keys: [publicJwk]
      });
    } catch (importError: any) {
      console.error('Key import error:', importError);
      return res.status(500).json({ 
        error: 'Key Processing Error', 
        details: importError.message 
      });
    }
  } catch (error: any) {
    console.error('JWKS error:', error);
    return res.status(500).json({ error: 'Internal Server Error', details: error.message });
  }
}
