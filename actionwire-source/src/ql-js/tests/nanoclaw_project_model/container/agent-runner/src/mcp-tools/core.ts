import fs from 'node:fs';

function registerTools(_tools: unknown[]) {}
function writeMessageOut(_message: unknown) {}
function getInboundDb() { return { prepare: (_sql: string) => ({ all: (_status?: string) => [] }) }; }

export const createAgent = {
  tool: { name: 'create_agent' },
  async handler(args: { name: string; instructions?: string }) {
    writeMessageOut({ kind: 'system', content: JSON.stringify({ action: 'create_agent', name: args.name, instructions: args.instructions }) });
  },
};

export const sendMessage = {
  tool: { name: 'send_message' },
  async handler(args: { to?: string; text: string }) {
    writeMessageOut({ kind: 'chat', content: JSON.stringify({ text: args.text }) });
  },
};

export const sendFile = {
  tool: { name: 'send_file' },
  async handler(args: { to?: string; path: string; text?: string; filename?: string }) {
    fs.copyFileSync(args.path, args.filename || '/workspace/outbox/file');
    writeMessageOut({ kind: 'chat', content: JSON.stringify({ text: args.text || '', files: [args.path] }) });
  },
};

export const editMessage = {
  tool: { name: 'edit_message' },
  async handler(args: { messageId: number; text: string }) {
    writeMessageOut({ kind: 'chat', content: JSON.stringify({ operation: 'edit', messageId: args.messageId, text: args.text }) });
  },
};

export const addReaction = {
  tool: { name: 'add_reaction' },
  async handler(args: { messageId: number; emoji: string }) {
    writeMessageOut({ kind: 'chat', content: JSON.stringify({ operation: 'reaction', messageId: args.messageId, emoji: args.emoji }) });
  },
};

export const askUserQuestion = {
  tool: { name: 'ask_user_question' },
  async handler(args: { title: string; question: string; options: string[]; timeout?: number }) {
    writeMessageOut({ kind: 'chat-sdk', content: JSON.stringify({ type: 'ask_question', title: args.title, question: args.question, options: args.options }) });
  },
};

export const sendCard = {
  tool: { name: 'send_card' },
  async handler(args: { card: object; fallbackText?: string }) {
    writeMessageOut({ kind: 'chat-sdk', content: JSON.stringify({ type: 'card', card: args.card, fallbackText: args.fallbackText }) });
  },
};

export const scheduleTask = {
  tool: { name: 'schedule_task' },
  async handler(args: { prompt: string; processAfter: string; recurrence?: string; script?: string }) {
    writeMessageOut({ kind: 'system', content: JSON.stringify({ action: 'schedule_task', ...args }) });
  },
};

export const listTasks = {
  tool: { name: 'list_tasks' },
  async handler(args: { status?: string }) {
    const db = getInboundDb();
    return db.prepare('SELECT * FROM messages_in').all(args.status);
  },
};

export const cancelTask = {
  tool: { name: 'cancel_task' },
  async handler(args: { taskId: string }) {
    writeMessageOut({ kind: 'system', content: JSON.stringify({ action: 'cancel_task', taskId: args.taskId }) });
  },
};

export const pauseTask = {
  tool: { name: 'pause_task' },
  async handler(args: { taskId: string }) {
    writeMessageOut({ kind: 'system', content: JSON.stringify({ action: 'pause_task', taskId: args.taskId }) });
  },
};

export const resumeTask = {
  tool: { name: 'resume_task' },
  async handler(args: { taskId: string }) {
    writeMessageOut({ kind: 'system', content: JSON.stringify({ action: 'resume_task', taskId: args.taskId }) });
  },
};

export const updateTask = {
  tool: { name: 'update_task' },
  async handler(args: { taskId: string; prompt?: string; processAfter?: string; recurrence?: string; script?: string }) {
    writeMessageOut({ kind: 'system', content: JSON.stringify({ action: 'update_task', ...args }) });
  },
};

const unregistered = { tool: { name: 'unregistered' }, async handler(args: unknown) { return args; } };
registerTools([
  createAgent, sendMessage, sendFile, editMessage, addReaction, askUserQuestion, sendCard,
  scheduleTask, listTasks, cancelTask, pauseTask, resumeTask, updateTask,
]);
void unregistered;
