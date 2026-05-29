import { VercelRequest, VercelResponse } from '@vercel/node';
import * as jose from 'jose';
import { randomUUID } from 'crypto';

const AGS_SCORE_SCOPE = 'https://purl.imsglobal.org/spec/lti-ags/scope/score';

/**
 * Принимает от фронта:
 *   {
 *     lineitem:     string  — URL lineitem из AGS-claim launch'а
 *     userId:       string  — sub пользователя из id_token
 *     scoreGiven:   number  — набранный балл
 *     scoreMaximum: number  — максимум
 *     comment?:     string
 *     iss?:         string  — issuer платформы (для вывода token endpoint)
 *   }
 *
 * Получает OAuth2 access token (client_credentials + JWT bearer, подпись
 * приватным ключом инструмента) и постит Score в Moodle gradebook.
 *
 * ПРИМЕЧАНИЕ ПО БЕЗОПАСНОСТИ: scoreGiven приходит с фронта. На учебном
 * стенде это приемлемо. Для защиты от накрутки нужно подтверждать
 * прохождение на сервере (отдельная доработка).
 */
export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed. Use POST.' });
  }

  try {
    const {
      lineitem,
      userId,
      scoreGiven,
      scoreMaximum,
      comment,
      iss,
    } = (req.body || {}) as Record<string, any>;

    if (!lineitem || !userId) {
      return res.status(400).json({ error: 'lineitem and userId are required' });
    }

    const clientId = process.env.LTI_CLIENT_ID || 'ItVsNxbE8B8vyOh';
    const issuer = iss || process.env.LTI_ISSUER || '';
    const tokenEndpoint =
      process.env.LTI_TOKEN_ENDPOINT ||
      (issuer ? `${issuer.replace(/\/$/, '')}/mod/lti/token.php` : '');

    if (!tokenEndpoint) {
      return res.status(400).json({
        error: 'token endpoint unknown — set LTI_TOKEN_ENDPOINT or pass iss',
      });
    }

    const privateKeyStr = (process.env.LTI_PRIVATE_KEY || '')
      .replace(/\\n/g, '\n')
      .trim();
    if (!privateKeyStr) {
      return res.status(500).json({ error: 'LTI_PRIVATE_KEY is not set' });
    }
    const privateKey = await jose.importPKCS8(privateKeyStr, 'RS256');

    // 1) client_assertion JWT
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new jose.SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'lti-key-1' })
      .setIssuer(clientId)
      .setSubject(clientId)
      .setAudience(tokenEndpoint)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .setJti(randomUUID())
      .sign(privateKey);

    // 2) access token
    const tokenResp = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
        scope: AGS_SCORE_SCOPE,
      }),
    });

    if (!tokenResp.ok) {
      const detail = await tokenResp.text();
      return res.status(502).json({
        error: 'token request failed',
        status: tokenResp.status,
        detail,
      });
    }
    const tokenJson: any = await tokenResp.json();
    const accessToken = tokenJson.access_token;
    if (!accessToken) {
      return res.status(502).json({ error: 'no access_token in response', tokenJson });
    }

    // 3) scores URL = lineitem + "/scores" (сохраняя query string)
    const scoresUrl = (() => {
      const u = new URL(lineitem);
      u.pathname = u.pathname.replace(/\/$/, '') + '/scores';
      return u.toString();
    })();

    const given = Number(scoreGiven ?? 0);
    const maximum = Number(scoreMaximum ?? 1);

    const scoreBody = {
      userId: String(userId),
      scoreGiven: given,
      scoreMaximum: maximum,
      comment: comment || undefined,
      timestamp: new Date().toISOString(),
      activityProgress: given >= maximum ? 'Completed' : 'Submitted',
      gradingProgress: 'FullyGraded',
    };

    const scoreResp = await fetch(scoresUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/vnd.ims.lis.v1.score+json',
      },
      body: JSON.stringify(scoreBody),
    });

    if (!scoreResp.ok) {
      const detail = await scoreResp.text();
      return res.status(502).json({
        error: 'score post failed',
        status: scoreResp.status,
        detail,
        scoresUrl,
      });
    }

    return res.status(200).json({ ok: true, scoreGiven: given, scoreMaximum: maximum });
  } catch (error: any) {
    console.error('Grade error:', error);
    return res.status(500).json({ error: error.message });
  }
}
