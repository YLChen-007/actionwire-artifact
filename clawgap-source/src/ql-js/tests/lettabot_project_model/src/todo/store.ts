import { readFileSync, writeFileSync } from 'node:fs';

function loadStore(path: string) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function saveStore(path: string, store: unknown) {
  writeFileSync(path, JSON.stringify(store));
}

function findTodoIndex(todos: unknown[], id: string) {
  const needle = id.trim();
  if (!needle) throw new Error('Todo ID is required');
  return todos.findIndex((todo) => String(todo).startsWith(needle));
}

function parseDateOrThrow(value: string, field: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new Error(`Invalid ${field}`);
  return parsed.toISOString();
}

export function addTodo(agentKey: string, input: { text: string }) {
  const text = input.text.trim();
  if (!text) throw new Error('Todo text is required');
  const store = loadStore(agentKey);
  saveStore(agentKey, { store, text });
}

export function completeTodo(agentKey: string, id: string) {
  const store = loadStore(agentKey);
  const idx = findTodoIndex(store.todos, id);
  saveStore(agentKey, { store, idx });
}

export function reopenTodo(agentKey: string, id: string) {
  const store = loadStore(agentKey);
  const idx = findTodoIndex(store.todos, id);
  saveStore(agentKey, { store, idx });
}

export function removeTodo(agentKey: string, id: string) {
  const store = loadStore(agentKey);
  const idx = findTodoIndex(store.todos, id);
  saveStore(agentKey, { store, idx });
}

export function snoozeTodo(agentKey: string, id: string, until: string) {
  const store = loadStore(agentKey);
  const idx = findTodoIndex(store.todos, id);
  const snoozedUntil = until ? parseDateOrThrow(until, 'snoozed_until') : null;
  saveStore(agentKey, { store, idx, snoozedUntil });
}
