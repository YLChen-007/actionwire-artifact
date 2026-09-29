declare const Bun: { spawnSync(argv: string[]): unknown };

export interface ActionDecision {
  action: string;
  command?: string;
  coordinates?: [number, number];
  text?: string;
  direction?: string;
  filename?: string;
  package?: string;
  url?: string;
  path?: string;
  source?: string;
  dest?: string;
  code?: number;
  setting?: string;
  skill?: string;
  query?: string;
}

export function runAdbCommand(command: string[], retries = 1) {
  if (retries < 0) throw new Error('bad retries');
  return Bun.spawnSync(['/usr/bin/adb', ...command]);
}

function validateCoordinates(coords: [number, number] | undefined): [number, number] | null {
  return coords && coords.length === 2 ? coords : null;
}

const SETTINGS_MAP: Record<string, string> = {
  wifi: 'android.settings.WIFI_SETTINGS',
};

export function executeAction(action: ActionDecision) {
  switch (action.action) {
    case 'tap': return executeTap(action);
    case 'type': return executeType(action);
    case 'enter': return executeEnter();
    case 'swipe': return executeSwipe(action);
    case 'home': return executeHome();
    case 'back': return executeBack();
    case 'wait': return executeWait();
    case 'done': return executeDone(action);
    case 'longpress': return executeLongPress(action);
    case 'screenshot': return executeScreenshot(action);
    case 'launch': return executeLaunch(action);
    case 'clear': return executeClear();
    case 'clipboard_get': return executeClipboardGet();
    case 'clipboard_set': return executeClipboardSet(action);
    case 'paste': return executePaste(action);
    case 'shell': return executeShell(action);
    case 'scroll': return executeScroll(action);
    case 'open_url': return executeOpenUrl(action);
    case 'switch_app': return executeSwitchApp(action);
    case 'notifications': return executeNotifications();
    case 'pull_file': return executePullFile(action);
    case 'push_file': return executePushFile(action);
    case 'keyevent': return executeKeyevent(action);
    case 'open_settings': return executeOpenSettings(action);
    // A literal without a resolved local callee is not an inventory entry.
    case 'unresolved': return missingAction(action);
    default: return null;
  }
}

function executeTap(action: ActionDecision) {
  const coords = validateCoordinates(action.coordinates);
  if (!coords) return null;
  return runAdbCommand(['shell', 'tap', String(coords)]);
}
function executeType(action: ActionDecision) {
  const text = action.text ?? '';
  if (!text) return null;
  const escapedText = text
    .replaceAll('\\', '\\\\')
    .replaceAll(' ', '%s');
  return runAdbCommand(['shell', 'text', escapedText]);
}
function executeEnter() { return runAdbCommand(['shell', 'enter']); }
function executeSwipe(action: ActionDecision) { return runAdbCommand(['shell', 'swipe', action.direction ?? '']); }
function executeHome() { return runAdbCommand(['shell', 'home']); }
function executeBack() { return runAdbCommand(['shell', 'back']); }
function executeWait() { return null; }
function executeDone(action: ActionDecision) { return action.action; }
function executeLongPress(action: ActionDecision) {
  const coords = validateCoordinates(action.coordinates);
  if (!coords) return null;
  return runAdbCommand(['shell', 'longpress', String(coords)]);
}
function executeScreenshot(action: ActionDecision) { return runAdbCommand(['pull', action.filename ?? 'screen.png']); }
function executeLaunch(action: ActionDecision) {
  const args = ['shell', 'launch', action.package ?? ''];
  return runAdbCommand(args);
}
function executeClear() { return runAdbCommand(['shell', 'clear']); }
function executeClipboardGet() { return runAdbCommand(['shell', 'clipboard-get']); }
function executeClipboardSet(action: ActionDecision) {
  const text = action.text ?? '';
  if (!text) return null;
  const escaped = text.replaceAll("'", "'\\''");
  return runAdbCommand(['shell', 'clipboard-set', escaped]);
}
function executePaste(action: ActionDecision) {
  return runAdbCommand(['shell', 'input', 'keyevent', '279']);
}
function executeShell(action: ActionDecision) {
  const cmd = action.command ?? '';
  if (!cmd) return null;
  return runAdbCommand(['shell', ...cmd.split(' ')]);
}
function executeScroll(action: ActionDecision) { return runAdbCommand(['shell', 'scroll', action.direction ?? '']); }
function executeOpenUrl(action: ActionDecision) {
  const url = action.url ?? '';
  if (!url) return null;
  return runAdbCommand(['shell', 'open-url', url]);
}
function executeSwitchApp(action: ActionDecision) {
  const pkg = action.package ?? '';
  if (!pkg) return null;
  return runAdbCommand(['shell', 'switch-app', pkg]);
}
function executeNotifications() { return runAdbCommand(['shell', 'notifications']); }
function executePullFile(action: ActionDecision) {
  const devicePath = action.path ?? '';
  if (!devicePath) return null;
  const filename = devicePath.split('/').pop() ?? 'file';
  const localPath = `./pulled_files/${filename}`;
  return runAdbCommand(['pull', devicePath, localPath]);
}
function executePushFile(action: ActionDecision) {
  const source = action.source ?? '';
  const dest = action.dest ?? '';
  if (!source || !dest) return null;
  return runAdbCommand(['push', source, dest]);
}
function executeKeyevent(action: ActionDecision) {
  const code = action.code;
  if (code == null) return null;
  return runAdbCommand(['shell', 'keyevent', String(code)]);
}
function executeOpenSettings(action: ActionDecision) {
  const setting = action.setting ?? '';
  const intentAction = SETTINGS_MAP[setting];
  if (!intentAction) return null;
  return runAdbCommand(['shell', 'settings', intentAction]);
}

function decoyAction(action: ActionDecision) { return action.action; }

export function unrelatedDispatcher(action: ActionDecision) {
  switch (action.action) {
    case 'decoy': return decoyAction(action);
    default: return null;
  }
}
