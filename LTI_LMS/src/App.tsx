import { useState, useEffect, useMemo } from 'react';
import {
  Key, Settings, ShieldCheck, GraduationCap, Copy, RefreshCw,
  CheckCircle2, BookOpen, Bug, Play, Code2, ArrowLeft,
  CheckCircle, XCircle, Loader2, AlertTriangle, Flag, Trophy,
  Info, Lock, ExternalLink, RotateCcw,
} from 'lucide-react';
import * as jose from 'jose';
import Editor from '@monaco-editor/react';

type LabSpec = {
  slug: string;
  title: string;
  vulnerability: string;
  description: string;
  instructions: string;
  order: number;
  run_path: string;
  check_path: string;
  verify_flag_path: string;
};

type CheckDetail = { ok: boolean; msg: string };
type CheckResult = {
  passed: boolean;
  summary: string;
  details: CheckDetail[];
};

type Progress = Record<string, { attack?: boolean; fix?: boolean; flag?: string }>;

const LIS_CLAIM = 'https://purl.imsglobal.org/spec/lti/claim/lis';
const CUSTOM_CLAIM = 'https://purl.imsglobal.org/spec/lti/claim/custom';
const CONTEXT_CLAIM = 'https://purl.imsglobal.org/spec/lti/claim/context';
const AGS_CLAIM = 'https://purl.imsglobal.org/spec/lti-ags/claim/endpoint';

function agsLineitem(launchData: any): string | null {
  return launchData?.raw?.[AGS_CLAIM]?.lineitem || null;
}

/** Отправляет оценку за лабу в Moodle (если AGS настроен). */
async function pushGrade(launchData: any, slug: string, progress: Progress): Promise<'ok' | 'no-ags' | 'error'> {
  const lineitem = agsLineitem(launchData);
  const sub = launchData?.raw?.sub;
  const iss = launchData?.raw?.iss;
  if (!lineitem || !sub) return 'no-ags';

  const p = progress[slug] || {};
  const done = (p.attack ? 1 : 0) + (p.fix ? 1 : 0);
  try {
    const r = await fetch('/api/grade', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        lineitem,
        iss,
        userId: sub,
        scoreGiven: done,
        scoreMaximum: 2,
        comment: `Лаба ${slug}: часть1=${!!p.attack}, часть2=${!!p.fix}`,
      }),
    });
    return r.ok ? 'ok' : 'error';
  } catch {
    return 'error';
  }
}

function displayName(data: any): string {
  if (!data) return 'Студент';
  const raw = data.raw || {};
  if (raw.name && raw.name.trim()) return raw.name;
  if (raw.given_name || raw.family_name) {
    return [raw.given_name, raw.family_name].filter(Boolean).join(' ');
  }
  if (data.name && data.name !== 'Пользователь' && data.name.trim()) return data.name;
  const sourcedId = raw[LIS_CLAIM]?.person_sourcedid;
  if (sourcedId) return sourcedId;
  if (raw.sub) return `Студент #${raw.sub}`;
  return 'Студент';
}

function displayEmail(data: any): string | null {
  if (!data) return null;
  const raw = data.raw || {};
  if (raw.email && raw.email !== 'no-email@mtuci.ru') return raw.email;
  if (data.email && data.email !== 'no-email@mtuci.ru' && data.email.trim()) return data.email;
  return null;
}

function privacyHidden(data: any): boolean {
  if (!data) return false;
  return (
    !displayEmail(data) &&
    (data.name === 'Пользователь' || !data.raw?.name) &&
    !data.raw?.given_name
  );
}

function userKey(data: any): string {
  const raw = data?.raw || {};
  if (raw.sub && raw.iss) return `${raw.sub}@${raw.iss}`;
  if (raw.sub) return String(raw.sub);
  return 'anon';
}

function loadProgress(key: string): Progress {
  try {
    return JSON.parse(localStorage.getItem(`lab_progress:${key}`) || '{}');
  } catch {
    return {};
  }
}

function saveProgress(key: string, slug: string, patch: Partial<Progress[string]>) {
  const cur = loadProgress(key);
  cur[slug] = { ...(cur[slug] || {}), ...patch };
  try {
    localStorage.setItem(`lab_progress:${key}`, JSON.stringify(cur));
  } catch {}
  window.dispatchEvent(new CustomEvent('lab-progress-changed'));
  return cur;
}

function resetAllProgress(key: string) {
  try {
    localStorage.removeItem(`lab_progress:${key}`);
  } catch {}
  window.dispatchEvent(new CustomEvent('lab-progress-changed'));
}

function resetLabProgress(key: string, slug: string) {
  const cur = loadProgress(key);
  delete cur[slug];
  try {
    localStorage.setItem(`lab_progress:${key}`, JSON.stringify(cur));
  } catch {}
  window.dispatchEvent(new CustomEvent('lab-progress-changed'));
}

function getDeepLinkSlug(launchData: any): string | null {
  const fromUrl = new URLSearchParams(window.location.search).get('lab');
  if (fromUrl) return fromUrl;
  const customLab = launchData?.raw?.[CUSTOM_CLAIM]?.lab;
  if (customLab) return String(customLab);
  return null;
}

function appendU(path: string, u: string): string {
  if (!u) return path;
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}u=${encodeURIComponent(u)}`;
}

// =========================================================================

function App() {
  const [launchData, setLaunchData] = useState<any>(null);
  const [isDemo, setIsDemo] = useState(false);
  const [keys, setKeys] = useState<{ privateKey: string; publicKey: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const [view, setView] = useState<'home' | 'labs' | 'lab'>('home');
  const [activeLab, setActiveLab] = useState<string | null>(null);

  // Авторесайз: Moodle показывает инструмент в iframe — сообщаем родителю
  // высоту контента, чтобы окно растягивалось без внутренней прокрутки.
  useEffect(() => {
    if (typeof window === 'undefined' || window.parent === window) return;
    const send = () => {
      const measured = Math.max(
        document.body.scrollHeight,
        document.documentElement.scrollHeight,
        document.body.offsetHeight,
        document.documentElement.offsetHeight
      );
      // Щедрый запас и минимум 1200px — Moodle часто даёт фиксированный
      // маленький iframe; просим явно побольше.
      const height = Math.max(measured + 80, 1200);
      const payload = { subject: 'lti.frameResize', height };
      try {
        window.parent.postMessage(payload, '*');
        window.parent.postMessage(JSON.stringify(payload), '*');
      } catch {}
    };
    send();
    const ro = new ResizeObserver(send);
    ro.observe(document.body);
    ro.observe(document.documentElement);
    window.addEventListener('load', send);
    const t = setInterval(send, 800);
    return () => {
      ro.disconnect();
      window.removeEventListener('load', send);
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const data = params.get('data') || params.get('launch_data');
    let parsed: any = null;
    if (data) {
      try {
        parsed = JSON.parse(decodeURIComponent(data));
        if (parsed && !Array.isArray(parsed.roles)) parsed.roles = [];
        setLaunchData(parsed);
      } catch {
        console.error('Failed to parse launch data');
      }
    }
    const slug = getDeepLinkSlug(parsed);
    if (slug) {
      setActiveLab(slug);
      setView('lab');
    }
  }, []);

  const generateKeys = async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256', {
      modulusLength: 2048,
    });
    const privateKeyPKCS8 = await jose.exportPKCS8(privateKey);
    const publicKeyJWK = await jose.exportJWK(publicKey);
    setKeys({
      privateKey: privateKeyPKCS8,
      publicKey: JSON.stringify(publicKeyJWK, null, 2),
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const startDemo = () => {
    setIsDemo(true);
    setLaunchData({
      name: 'Иван Иванов (Демо)',
      email: 'student@mtuci.ru',
      roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
      course: 'Разработка веб-приложений (LTI 1.3)',
      raw: {
        sub: 'demo-001',
        iss: 'https://lms.mtuci.ru/lms',
        [LIS_CLAIM]: { person_sourcedid: 'ДЕМО-001' },
      },
    });
  };

  if (view === 'lab' && activeLab) {
    return (
      <LabView
        slug={activeLab}
        launchData={launchData}
        onBack={() => { setView('labs'); setActiveLab(null); }}
      />
    );
  }

  if (view === 'labs') {
    return (
      <LabsList
        launchData={launchData}
        onBack={() => setView('home')}
        onOpenLab={(slug) => { setActiveLab(slug); setView('lab'); }}
      />
    );
  }

  if (launchData) {
    return (
      <Dashboard
        launchData={launchData}
        isDemo={isDemo}
        onOpenLabs={() => setView('labs')}
      />
    );
  }

  const appUrl = window.location.origin;
  const clientId = 'ItVsNxbE8B8vyOh';

  return (
    <div className="min-h-screen bg-slate-50 p-4 md:p-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-black text-slate-900 tracking-tight">Интеграция LTI 1.3 для MTUCI</h1>
          <p className="text-slate-600 text-lg max-w-2xl mx-auto">
            Настройте ваше внешнее средство за несколько минут. Сгенерируйте ключи и скопируйте ссылки в Moodle.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <button
              onClick={startDemo}
              className="inline-flex items-center gap-2 bg-slate-900 text-white px-6 py-3 rounded-xl font-bold hover:bg-slate-800 transition-all shadow-lg hover:shadow-xl active:scale-95"
            >
              <GraduationCap className="w-5 h-5" />
              Запустить демо-версию инструмента
            </button>
            <button
              onClick={() => setView('labs')}
              className="inline-flex items-center gap-2 bg-blue-600 text-white px-6 py-3 rounded-xl font-bold hover:bg-blue-700 transition-all shadow-lg hover:shadow-xl active:scale-95"
            >
              <Bug className="w-5 h-5" />
              Открыть лаборатории
            </button>
          </div>
        </div>

        <div className="bg-gradient-to-br from-blue-600 to-indigo-700 p-8 rounded-3xl shadow-xl text-white">
          <div className="flex items-center gap-3 mb-6">
            <Key className="w-8 h-8" />
            <h2 className="text-2xl font-bold italic">Шаг 1: Создание ключей безопасности</h2>
          </div>
          <div className="space-y-6">
            <p className="opacity-90">
              Для работы LTI 1.3 требуются RSA ключи. Нажмите кнопку ниже, чтобы создать их прямо в браузере.
            </p>
            {!keys ? (
              <button
                onClick={generateKeys}
                className="w-full bg-white text-blue-700 py-4 rounded-2xl font-black text-lg shadow-inner hover:bg-blue-50 transition-all flex items-center justify-center gap-3"
              >
                <RefreshCw className="w-6 h-6" />
                СГЕНЕРИРОВАТЬ RSA КЛЮЧИ
              </button>
            ) : (
              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between items-center text-sm font-bold uppercase tracking-wider opacity-75">
                    <span>Ваш Приватный Ключ (Private Key)</span>
                    <button
                      onClick={() => copyToClipboard(keys.privateKey)}
                      className="flex items-center gap-1 hover:text-blue-200 transition-colors"
                    >
                      {copied ? <CheckCircle2 className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      {copied ? 'Скопировано!' : 'Копировать'}
                    </button>
                  </div>
                  <pre className="bg-blue-900/50 p-4 rounded-xl text-xs font-mono overflow-x-auto border border-blue-400/30 max-h-40 whitespace-pre-wrap">
                    {keys.privateKey}
                  </pre>
                  <p className="text-xs bg-amber-400 text-amber-900 px-3 py-2 rounded-lg font-bold">
                    ВАЖНО: Вставьте этот ключ в Vercel в переменную окружения LTI_PRIVATE_KEY
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="bg-white p-8 rounded-3xl shadow-sm border border-slate-200">
          <div className="flex items-center gap-3 mb-8">
            <Settings className="w-8 h-8 text-blue-600" />
            <h2 className="text-2xl font-bold text-slate-900">Шаг 2: Настройка в Moodle МТУСИ</h2>
          </div>
          <div className="grid grid-cols-1 gap-6">
            <ConfigRow label="ID клиента (Client ID)" value={clientId} desc="Уже прописан в коде приложения" />
            <ConfigRow label="URL-адрес инициирования входа" value={`${appUrl}/api/init`} desc="Initiate login URL" />
            <ConfigRow label="URI перенаправления" value={`${appUrl}/api/launch`} desc="Redirection URI" />
            <ConfigRow label="URL-адрес набора ключей" value={`${appUrl}/api/jwks`} desc="Public keyset (JWKS) URL" />
          </div>
          <div className="mt-8 p-6 bg-slate-50 rounded-2xl border border-dashed border-slate-300 space-y-3">
            <p className="text-slate-600 text-sm">
              Issuer: <code className="bg-white px-2 py-1 rounded border border-slate-200 text-blue-600">https://lms.mtuci.ru/lms</code>
            </p>
            <p className="text-slate-600 text-sm flex items-start gap-2">
              <Info className="w-4 h-4 mt-0.5 shrink-0 text-blue-500" />
              <span>
                Чтобы открывать конкретную лабу при запуске из Moodle, в настройках активности
                задайте <b>Custom parameter</b>: <code className="bg-white px-1.5 py-0.5 rounded border border-slate-200 text-blue-600">lab=sqli</code>{' '}
                (или <code className="bg-white px-1.5 py-0.5 rounded border border-slate-200 text-blue-600">xss</code>, <code className="bg-white px-1.5 py-0.5 rounded border border-slate-200 text-blue-600">idor</code>, <code className="bg-white px-1.5 py-0.5 rounded border border-slate-200 text-blue-600">cmdi</code>, <code className="bg-white px-1.5 py-0.5 rounded border border-slate-200 text-blue-600">path_traversal</code>).
              </span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// =========================================================================
// Dashboard
// =========================================================================

function Dashboard({
  launchData, isDemo, onOpenLabs,
}: {
  launchData: any;
  isDemo: boolean;
  onOpenLabs: () => void;
}) {
  const name = displayName(launchData);
  const email = displayEmail(launchData);
  const hidden = privacyHidden(launchData);
  const userId = userKey(launchData);
  const sourcedId = launchData.raw?.[LIS_CLAIM]?.person_sourcedid;
  const course =
    launchData.raw?.[CONTEXT_CLAIM]?.title ||
    launchData.course ||
    'Курс МТУСИ';
  const courseLabel =
    launchData.raw?.[CONTEXT_CLAIM]?.label ||
    launchData.context?.label;

  const [tick, setTick] = useState(0);
  useEffect(() => {
    const f = () => setTick(x => x + 1);
    window.addEventListener('lab-progress-changed', f);
    window.addEventListener('storage', f);
    return () => {
      window.removeEventListener('lab-progress-changed', f);
      window.removeEventListener('storage', f);
    };
  }, []);

  const progress = useMemo(() => loadProgress(userId), [userId, tick]);
  const totalLabs = 5;
  const fullyDone = Object.values(progress).filter((p) => p.attack && p.fix).length;
  const partialDone = Object.values(progress).filter((p) => (p.attack || p.fix) && !(p.attack && p.fix)).length;

  const isLearner =
    launchData.roles &&
    Array.isArray(launchData.roles) &&
    launchData.roles.some((r: any) => typeof r === 'string' && r.toLowerCase().includes('learner'));

  const onResetAll = () => {
    if (confirm('Сбросить прогресс по всем лабораторным? Это нельзя отменить.')) {
      resetAllProgress(userId);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 p-4 md:p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        <header className="flex justify-between items-center bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
          <div className="flex items-center gap-4">
            <div className="bg-blue-600 p-3 rounded-xl">
              <ShieldCheck className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-900">LTI 1.3 Инструмент</h1>
              <p className="text-slate-500">Запущено из MTUCI LMS</p>
            </div>
          </div>
          {isDemo && (
            <span className="bg-amber-100 text-amber-700 px-4 py-1 rounded-full text-sm font-medium border border-amber-200">
              Режим симуляции
            </span>
          )}
        </header>

        {hidden && (
          <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 flex items-start gap-3">
            <Lock className="w-5 h-5 text-amber-600 mt-0.5 shrink-0" />
            <div className="text-sm text-amber-900">
              <b>Moodle скрыл имя и email пользователя.</b>{' '}
              Чтобы инструмент видел реальное ФИО, в настройках LTI-инструмента в Moodle
              включите «<i>Share launcher's name with tool</i>» и «<i>Share launcher's email with tool</i>».
              Пока используется студенческий номер из <code className="bg-amber-100 px-1 rounded">person_sourcedid</code>.
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 space-y-1">
            <p className="text-slate-500 text-sm">Пользователь</p>
            <h3 className="text-xl font-semibold text-slate-900">{name}</h3>
            {sourcedId && sourcedId !== name && (
              <p className="text-slate-400 text-xs font-mono">{sourcedId}</p>
            )}
            {email && <p className="text-slate-400 text-sm">{email}</p>}
          </div>
          <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 space-y-2">
            <p className="text-slate-500 text-sm">Роль</p>
            <h3 className="text-xl font-semibold">{isLearner ? 'Студент' : 'Преподаватель'}</h3>
            <p className="text-slate-400 text-sm">LTI Role Access</p>
          </div>
          <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 space-y-2">
            <p className="text-slate-500 text-sm">Курс</p>
            <h3 className="text-base font-semibold leading-tight">{course}</h3>
            {courseLabel && <p className="text-slate-400 text-sm">{courseLabel}</p>}
          </div>
        </div>

        <div className="bg-gradient-to-br from-blue-600 to-indigo-700 p-8 rounded-3xl shadow-xl text-white">
          <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <Bug className="w-8 h-8" />
                <h2 className="text-2xl font-bold">Лабораторные работы по веб-безопасности</h2>
              </div>
              <p className="opacity-90 max-w-xl">
                Пять уязвимых приложений: SQL Injection, Stored XSS, IDOR, Command Injection, Path Traversal.
                В каждой — атака и написание безопасного кода.
              </p>
            </div>
            <div className="flex items-center gap-2 bg-white/15 backdrop-blur-sm px-4 py-2 rounded-2xl border border-white/20">
              <Trophy className="w-5 h-5" />
              <span className="font-bold text-lg">{fullyDone}/{totalLabs}</span>
              <span className="text-sm opacity-80">пройдено</span>
            </div>
          </div>

          <div className="h-2 rounded-full bg-white/20 overflow-hidden mb-5">
            <div
              className="h-full bg-emerald-400 transition-all"
              style={{ width: `${(fullyDone / totalLabs) * 100}%` }}
            />
          </div>

          <div className="flex flex-wrap gap-3 items-center">
            <button
              onClick={onOpenLabs}
              className="bg-white text-blue-700 px-6 py-3 rounded-xl font-bold hover:bg-blue-50 transition-all shadow-lg hover:shadow-xl active:scale-95 inline-flex items-center gap-2"
            >
              <BookOpen className="w-5 h-5" />
              {fullyDone > 0 ? 'Продолжить' : 'Открыть список лаб'}
            </button>
            {partialDone > 0 && (
              <span className="text-sm opacity-80">
                ещё {partialDone} начато
              </span>
            )}
            {(fullyDone > 0 || partialDone > 0) && (
              <button
                onClick={onResetAll}
                className="bg-white/10 hover:bg-white/20 px-4 py-2 rounded-xl font-medium text-sm border border-white/20 inline-flex items-center gap-2 transition-all"
              >
                <RotateCcw className="w-4 h-4" />
                Сбросить прогресс
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// =========================================================================
// Список лаб
// =========================================================================

function LabsList({
  launchData, onBack, onOpenLab,
}: {
  launchData: any;
  onBack: () => void;
  onOpenLab: (slug: string) => void;
}) {
  const [labs, setLabs] = useState<LabSpec[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const userId = userKey(launchData);

  const [tick, setTick] = useState(0);
  useEffect(() => {
    const f = () => setTick((x) => x + 1);
    window.addEventListener('lab-progress-changed', f);
    return () => window.removeEventListener('lab-progress-changed', f);
  }, []);

  const progress = useMemo(() => loadProgress(userId), [userId, tick]);

  useEffect(() => {
    fetch('/labs')
      .then((r) => r.json())
      .then((data) => setLabs(data.labs || []))
      .catch((e) => setError(String(e)));
  }, []);

  const greeting = displayName(launchData);

  return (
    <div className="min-h-screen bg-slate-50 p-4 md:p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-2 text-slate-600 hover:text-slate-900 font-medium"
        >
          <ArrowLeft className="w-4 h-4" /> Назад
        </button>

        <div className="bg-gradient-to-br from-blue-600 to-indigo-700 p-8 rounded-3xl text-white shadow-xl">
          <div className="flex items-center gap-3 mb-2">
            <Bug className="w-8 h-8" />
            <h1 className="text-3xl font-black">Лабораторные работы</h1>
          </div>
          <p className="opacity-90">
            {greeting !== 'Студент' ? `${greeting}, в каждой лабе ` : 'В каждой лабе '}
            две части: атака на уязвимое приложение и исправление кода.
          </p>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-2xl p-4 text-red-800 flex items-start gap-2">
            <AlertTriangle className="w-5 h-5 mt-0.5 shrink-0" />
            <div>
              <b>Ошибка загрузки списка:</b> {error}
            </div>
          </div>
        )}

        {!labs && !error && (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
          </div>
        )}

        {labs && (
          <div className="grid grid-cols-1 gap-4">
            {labs.map((lab, idx) => {
              const p = progress[lab.slug] || {};
              const fullyDone = p.attack && p.fix;
              return (
                <button
                  key={lab.slug}
                  onClick={() => onOpenLab(lab.slug)}
                  className={`text-left bg-white p-6 rounded-2xl shadow-sm border transition-all group ${
                    fullyDone
                      ? 'border-emerald-300 hover:border-emerald-400'
                      : 'border-slate-200 hover:border-blue-300'
                  } hover:shadow-md`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-xs font-mono text-slate-400">№{idx + 1}</span>
                        <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-blue-100 text-blue-700">
                          {lab.vulnerability}
                        </span>
                        {p.attack && (
                          <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 inline-flex items-center gap-1">
                            <Flag className="w-3 h-3" /> атака
                          </span>
                        )}
                        {p.fix && (
                          <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 inline-flex items-center gap-1">
                            <Code2 className="w-3 h-3" /> код
                          </span>
                        )}
                      </div>
                      <h3 className={`text-lg font-bold mb-1 ${
                        fullyDone ? 'text-emerald-800 group-hover:text-emerald-900'
                                  : 'text-slate-900 group-hover:text-blue-700'
                      }`}>
                        {lab.title}
                      </h3>
                      <p className="text-slate-600 text-sm">{lab.description}</p>
                    </div>
                    {fullyDone ? (
                      <CheckCircle className="w-6 h-6 text-emerald-500 mt-1 shrink-0" />
                    ) : (
                      <Play className="w-5 h-5 text-slate-300 group-hover:text-blue-600 mt-1 shrink-0" />
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// =========================================================================
// Конкретная лаба
// =========================================================================

function LabView({
  slug, launchData, onBack,
}: { slug: string; launchData: any; onBack: () => void }) {
  const [spec, setSpec] = useState<LabSpec | null>(null);
  const [template, setTemplate] = useState<string>('');
  const [code, setCode] = useState<string>('');
  const [result, setResult] = useState<CheckResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [tab, setTab] = useState<'attack' | 'fix'>('attack');

  const [flagInput, setFlagInput] = useState('');
  const [flagResult, setFlagResult] = useState<{ ok: boolean } | null>(null);
  const [flagChecking, setFlagChecking] = useState(false);
  const [gradeStatus, setGradeStatus] = useState<'idle' | 'sending' | 'ok' | 'error' | 'no-ags'>('idle');
  const [gradeError, setGradeError] = useState<string | null>(null);
  const [variant, setVariant] = useState<{ name: string; label: string } | null>(null);

  const userId = userKey(launchData);
  const [tick, setTick] = useState(0);
  const progress = useMemo(() => loadProgress(userId), [userId, tick]);
  const p = progress[slug] || {};

  useEffect(() => {
    fetch(appendU(`/labs/${slug}/template`, userId))
      .then((r) => r.json())
      .then((data) => {
        setSpec(data.spec);
        setTemplate(data.template);
        setCode(data.template);
        setVariant(data.variant || null);
      });
    const initial = loadProgress(userId)[slug] || {};
    if (initial.flag) setFlagInput(initial.flag);
  }, [slug]);

  const checkCode = async () => {
    setChecking(true);
    setResult(null);
    try {
      const r = await fetch(appendU(`/labs/${slug}/check`, userId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await r.json();
      setResult(data);
      if (data.passed) {
        const updated = saveProgress(userId, slug, { fix: true });
        setTick((x) => x + 1);
        sendGrade(updated);
      }
    } catch (e) {
      setResult({ passed: false, summary: 'Ошибка сети: ' + String(e), details: [] });
    } finally {
      setChecking(false);
    }
  };

  const verifyFlag = async () => {
    setFlagChecking(true);
    setFlagResult(null);
    try {
      const r = await fetch(appendU(`/labs/${slug}/verify-flag`, userId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flag: flagInput }),
      });
      const data = await r.json();
      setFlagResult({ ok: !!data.ok });
      if (data.ok) {
        const updated = saveProgress(userId, slug, { attack: true, flag: flagInput.trim() });
        setTick((x) => x + 1);
        sendGrade(updated);
      }
    } catch {
      setFlagResult({ ok: false });
    } finally {
      setFlagChecking(false);
    }
  };

  const sendGrade = async (updatedProgress: Progress) => {
    if (!agsLineitem(launchData)) {
      setGradeStatus('no-ags');
      return;
    }
    setGradeStatus('sending');
    setGradeError(null);
    const sub = launchData?.raw?.sub;
    const iss = launchData?.raw?.iss;
    const lineitem = agsLineitem(launchData);
    const p = updatedProgress[slug] || {};
    const done = (p.attack ? 1 : 0) + (p.fix ? 1 : 0);
    try {
      const r = await fetch('/api/grade', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          lineitem, iss, userId: sub,
          scoreGiven: done, scoreMaximum: 2,
          comment: `Лаба ${slug}: часть1=${!!p.attack}, часть2=${!!p.fix}`,
        }),
      });
      if (r.ok) {
        setGradeStatus('ok');
      } else {
        setGradeStatus('error');
        try {
          const txt = await r.text();
          setGradeError(`${r.status}: ${txt.slice(0, 500)}`);
        } catch {
          setGradeError(`HTTP ${r.status}`);
        }
      }
    } catch (e: any) {
      setGradeStatus('error');
      setGradeError(String(e?.message || e));
    }
  };

  const onResetLab = () => {
    if (confirm(`Сбросить прогресс лабораторной «${spec?.title}»?`)) {
      resetLabProgress(userId, slug);
      setFlagInput('');
      setFlagResult(null);
      setResult(null);
      setCode(template);
      setTick((x) => x + 1);
    }
  };

  if (!spec) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin text-slate-400" />
      </div>
    );
  }

  const runUrl = appendU(spec.run_path, userId);
  const labHasProgress = p.attack || p.fix;

  return (
    <div className="min-h-screen bg-slate-50 p-4 md:p-8">
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <button
            onClick={onBack}
            className="inline-flex items-center gap-2 text-slate-600 hover:text-slate-900 font-medium"
          >
            <ArrowLeft className="w-4 h-4" /> К списку лаб
          </button>
          {labHasProgress && (
            <button
              onClick={onResetLab}
              className="text-sm text-slate-500 hover:text-slate-800 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 hover:border-slate-300 bg-white"
            >
              <RotateCcw className="w-4 h-4" /> Сбросить эту лабу
            </button>
          )}
        </div>

        <header className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-blue-100 text-blue-700">
              {spec.vulnerability}
            </span>
            {p.attack && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 inline-flex items-center gap-1">
                <CheckCircle className="w-3 h-3" /> Часть 1
              </span>
            )}
            {p.fix && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 inline-flex items-center gap-1">
                <CheckCircle className="w-3 h-3" /> Часть 2
              </span>
            )}
            {gradeStatus === 'sending' && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 inline-flex items-center gap-1">
                <Loader2 className="w-3 h-3 animate-spin" /> отправка оценки…
              </span>
            )}
            {gradeStatus === 'ok' && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 inline-flex items-center gap-1">
                <CheckCircle className="w-3 h-3" /> оценка в Moodle
              </span>
            )}
            {gradeStatus === 'error' && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 inline-flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" /> оценка не отправлена
              </span>
            )}
            {variant && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 ml-auto">
                Стенд: {variant.label}
              </span>
            )}
          </div>
          <h1 className="text-2xl font-bold text-slate-900 mb-2">{spec.title}</h1>
          <p className="text-slate-600">{spec.description}</p>
          <div className="mt-4 p-4 bg-slate-50 rounded-xl border border-slate-100 whitespace-pre-line text-sm text-slate-700">
            {spec.instructions}
          </div>
          {gradeStatus === 'error' && gradeError && (
            <div className="mt-3 p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs font-mono text-amber-900 whitespace-pre-wrap break-all">
              Ошибка отправки оценки: {gradeError}
            </div>
          )}
        </header>

        <div className="flex gap-2 border-b border-slate-200">
          <button
            onClick={() => setTab('attack')}
            className={`px-4 py-2 font-semibold text-sm border-b-2 transition-colors ${
              tab === 'attack'
                ? 'border-blue-600 text-blue-700'
                : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}
          >
            <Bug className="w-4 h-4 inline mr-1" /> Часть 1: атака
            {p.attack && <CheckCircle className="w-4 h-4 inline ml-1 text-emerald-500" />}
          </button>
          <button
            onClick={() => setTab('fix')}
            className={`px-4 py-2 font-semibold text-sm border-b-2 transition-colors ${
              tab === 'fix'
                ? 'border-blue-600 text-blue-700'
                : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}
          >
            <Code2 className="w-4 h-4 inline mr-1" /> Часть 2: безопасный код
            {p.fix && <CheckCircle className="w-4 h-4 inline ml-1 text-emerald-500" />}
          </button>
        </div>

        {tab === 'attack' && (
          <div className="space-y-4">
            <div className="bg-white rounded-2xl border border-slate-200 p-6">
              <div className="flex items-center gap-2 mb-3">
                <ExternalLink className="w-5 h-5 text-blue-600" />
                <h3 className="font-bold text-slate-900">Уязвимое приложение</h3>
              </div>
              <p className="text-sm text-slate-600 mb-4">
                Откройте уязвимое приложение в новой вкладке, проведите атаку и скопируйте найденный флаг.
              </p>
              <a
                href={runUrl}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-2 bg-blue-600 text-white px-5 py-2.5 rounded-xl font-bold hover:bg-blue-700 transition-all shadow active:scale-95"
              >
                <ExternalLink className="w-4 h-4" />
                Открыть в новой вкладке
              </a>
            </div>

            <div className="bg-white rounded-2xl border border-slate-200 p-5 space-y-3">
              <div className="flex items-center gap-2 flex-wrap">
                <Flag className="w-5 h-5 text-blue-600" />
                <h3 className="font-bold text-slate-900">Вставьте найденный флаг</h3>
                {p.attack && (
                  <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700">
                    Принято
                  </span>
                )}
              </div>
              <div className="flex flex-wrap gap-2">
                <input
                  type="text"
                  value={flagInput}
                  onChange={(e) => setFlagInput(e.target.value)}
                  spellCheck={false}
                  placeholder="FLAG{...}"
                  className="flex-1 min-w-[260px] px-4 py-2.5 rounded-xl border border-slate-300 font-mono text-sm focus:outline-none focus:border-blue-500"
                />
                <button
                  onClick={verifyFlag}
                  disabled={flagChecking || !flagInput.trim()}
                  className="inline-flex items-center gap-2 bg-blue-600 text-white px-5 py-2.5 rounded-xl font-bold hover:bg-blue-700 transition-all shadow disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {flagChecking
                    ? <><Loader2 className="w-4 h-4 animate-spin" /> Проверяю…</>
                    : <><CheckCircle className="w-4 h-4" /> Проверить</>}
                </button>
              </div>
              {flagResult && (
                <div className={`flex items-start gap-2 text-sm p-3 rounded-xl ${
                  flagResult.ok
                    ? 'bg-emerald-50 text-emerald-900 border border-emerald-200'
                    : 'bg-amber-50 text-amber-900 border border-amber-200'
                }`}>
                  {flagResult.ok
                    ? <><CheckCircle className="w-4 h-4 mt-0.5 shrink-0" /><span>Флаг верный — Часть 1 засчитана!</span></>
                    : <><XCircle className="w-4 h-4 mt-0.5 shrink-0" /><span>Флаг не совпал. Проверьте, что взяли его полностью, со скобками.</span></>}
                </div>
              )}
            </div>
          </div>
        )}

        {tab === 'fix' && (
          <div className="space-y-4">
            <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 bg-slate-100 border-b border-slate-200">
                <span className="text-xs font-mono text-slate-600">solution.py</span>
                <button
                  onClick={() => setCode(template)}
                  className="text-xs text-slate-500 hover:text-slate-700 inline-flex items-center gap-1"
                >
                  <RefreshCw className="w-3 h-3" /> Сбросить к шаблону
                </button>
              </div>
              <Editor
                height="460px"
                language="python"
                value={code}
                onChange={(v) => setCode(v ?? '')}
                theme="vs-dark"
                loading={<div className="p-10 text-slate-400 text-center bg-slate-900">Загрузка редактора…</div>}
                options={{
                  fontSize: 13,
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  automaticLayout: true,
                  fontFamily: 'ui-monospace, "JetBrains Mono", monospace',
                  padding: { top: 12, bottom: 12 },
                  lineNumbers: 'on',
                  folding: false,
                  tabSize: 4,
                  insertSpaces: true,
                }}
              />
            </div>

            <div>
              <button
                onClick={checkCode}
                disabled={checking}
                className="inline-flex items-center gap-2 bg-blue-600 text-white px-6 py-3 rounded-xl font-bold hover:bg-blue-700 transition-all shadow-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {checking
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Проверяю…</>
                  : <><CheckCircle className="w-4 h-4" /> Проверить решение</>}
              </button>
            </div>

            {result && (
              <div className={`rounded-2xl border p-5 ${
                result.passed ? 'bg-emerald-50 border-emerald-200' : 'bg-amber-50 border-amber-200'
              }`}>
                <div className="flex items-start gap-3 mb-3">
                  {result.passed
                    ? <CheckCircle className="w-6 h-6 text-emerald-600 shrink-0 mt-0.5" />
                    : <XCircle className="w-6 h-6 text-amber-600 shrink-0 mt-0.5" />}
                  <div className="flex-1">
                    <div className={`font-bold ${result.passed ? 'text-emerald-900' : 'text-amber-900'}`}>
                      {result.passed ? 'Решение принято — Часть 2 засчитана' : 'Решение не принято'}
                    </div>
                    <div className={`text-sm mt-1 ${result.passed ? 'text-emerald-800' : 'text-amber-800'}`}>
                      {result.summary}
                    </div>
                  </div>
                </div>

                {result.details && result.details.length > 0 && (
                  <ul className="mt-3 space-y-1.5">
                    {result.details.map((d, i) => (
                      <li key={i} className={`text-sm flex items-start gap-2 ${
                        d.ok ? 'text-emerald-700' : 'text-amber-800'
                      }`}>
                        {d.ok
                          ? <CheckCircle className="w-4 h-4 mt-0.5 shrink-0" />
                          : <XCircle className="w-4 h-4 mt-0.5 shrink-0" />}
                        <span>{d.msg}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// =========================================================================

function ConfigRow({ label, value, desc }: { label: string; value: string; desc: string }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex flex-col md:flex-row md:items-center justify-between p-4 bg-slate-50 rounded-2xl border border-slate-100 hover:border-blue-200 transition-colors group">
      <div className="mb-2 md:mb-0">
        <p className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-1">{desc}</p>
        <p className="text-sm font-semibold text-slate-900">{label}</p>
        <p className="text-blue-600 font-mono text-sm break-all">{value}</p>
      </div>
      <button
        onClick={copy}
        className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold transition-all ${
          copied
            ? 'bg-green-100 text-green-700 border border-green-200'
            : 'bg-white text-slate-600 border border-slate-200 shadow-sm hover:shadow-md'
        }`}
      >
        {copied ? <CheckCircle2 className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
        {copied ? 'Готово!' : 'Копировать'}
      </button>
    </div>
  );
}

export default App;
