import { runAdbCommand, type ActionDecision } from './actions';

interface UIElement { text: string; }

export function executeSkill(decision: ActionDecision, elements: UIElement[]) {
  const skill = decision.skill ?? decision.action;
  switch (skill) {
    case 'read_screen': return readScreen(elements);
    case 'submit_message': return submitMessage(elements);
    case 'copy_visible_text': return copyVisibleText(decision, elements);
    case 'wait_for_content': return waitForContent(elements);
    case 'find_and_tap': return findAndTap(decision, elements);
    case 'compose_email': return composeEmail(decision, elements);
    default: return null;
  }
}

function readScreen(elements: UIElement[]) { return elements.map((element) => element.text).join('\n'); }
function submitMessage(elements: UIElement[]) { return runAdbCommand(['shell', 'tap', elements[0]?.text ?? '']); }
function safeClipboardSet(text: string) { return runAdbCommand(['shell', 'clipboard-set', text]); }
function copyVisibleText(decision: ActionDecision, elements: UIElement[]) {
  let textElements = elements;
  if (decision.query) {
    const query = decision.query.toLowerCase();
    textElements = textElements.filter((el) => el.text.toLowerCase().includes(query));
  }
  if (textElements.length === 0) {
    textElements = elements;
    if (decision.query) {
      const query = decision.query.toLowerCase();
      textElements = textElements.filter((el) => el.text.toLowerCase().includes(query));
    }
  }
  if (textElements.length === 0) return null;
  return safeClipboardSet(textElements.map((el) => el.text).join('\n'));
}
function waitForContent(elements: UIElement[]) { return elements.length; }

function findMatch(elements: UIElement[], queryLower: string): UIElement | null {
  const matches = elements.filter((el) => el.text.toLowerCase().includes(queryLower));
  return matches[0] ?? null;
}

function findAndTap(decision: ActionDecision, elements: UIElement[]) {
  const query = decision.query;
  if (!query) return null;
  const queryLower = query.toLowerCase();
  const best = findMatch(elements, queryLower);
  if (!best) return null;
  return runAdbCommand(['shell', 'tap', best.text]);
}
function composeEmail(decision: ActionDecision, elements: UIElement[]) {
  const emailAddress = decision.query;
  if (!emailAddress) return null;
  return runAdbCommand([
    'shell', 'am', 'start', '-a', 'android.intent.action.SENDTO',
    '-d', `mailto:${emailAddress}`,
  ]);
}

// Same-looking switch, but it is not the audited executeSkill dispatcher.
export function unrelatedSkill(decision: ActionDecision, elements: UIElement[]) {
  const skill = decision.skill ?? decision.action;
  switch (skill) {
    case 'decoy_skill': return copyVisibleText(decision, elements);
    default: return null;
  }
}
