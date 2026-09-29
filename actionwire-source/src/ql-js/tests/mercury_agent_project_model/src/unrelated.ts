import { readFileSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';

export const ordinary = { execute: ({ path }: { path: string }) => readFileSync(path) };
export function persistence(path: string, content: string) { writeFileSync(path, content); }
export function process(command: string) { return spawn(command); }
