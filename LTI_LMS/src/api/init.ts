import { VercelRequest, VercelResponse } from '@vercel/node';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Moodle can send params in GET or POST
  const params = req.method === 'POST' ? req.body : req.query;
  
  const iss = params.iss;
  const login_hint = params.login_hint;
  const lti_message_hint = params.lti_message_hint;

  if (!iss || !login_hint) {
    return res.status(400).send(`
      <html>
        <body style="font-family: sans-serif; padding: 2rem; line-height: 1.5;">
          <h1 style="color: #e11d48;">Ошибка инициации LTI</h1>
          <p>Отсутствуют обязательные параметры (iss, login_hint).</p>
          <p>Эта ссылка предназначена для автоматического вызова из Moodle. Пожалуйста, запустите инструмент из вашего курса в МТУСИ.</p>
          <hr />
          <p style="font-size: 0.875rem; color: #64748b;">Debug: ${JSON.stringify(params)}</p>
        </body>
      </html>
    `);
  }

  // Get config from env or defaults
  const auth_endpoint = process.env.LTI_OIDC_AUTH_ENDPOINT || 'https://lms.mtuci.ru/lms/mod/lti/auth.php';
  const client_id = process.env.LTI_CLIENT_ID || 'ItVsNxbE8B8vyOh';

  const authUrl = new URL(auth_endpoint);
  authUrl.searchParams.append('scope', 'openid');
  authUrl.searchParams.append('response_type', 'id_token');
  authUrl.searchParams.append('client_id', client_id);
  // Important: The redirect_uri must exactly match one of the URIs registered in Moodle
  const redirectUri = `https://${req.headers.host}/api/launch`;
  authUrl.searchParams.append('redirect_uri', redirectUri);
  authUrl.searchParams.append('login_hint', login_hint);
  authUrl.searchParams.append('state', Math.random().toString(36).substring(7));
  authUrl.searchParams.append('nonce', Math.random().toString(36).substring(7));
  authUrl.searchParams.append('prompt', 'none');
  authUrl.searchParams.append('response_mode', 'form_post');
  if (lti_message_hint) {
    authUrl.searchParams.append('lti_message_hint', lti_message_hint);
  }

  res.redirect(authUrl.toString());
}
