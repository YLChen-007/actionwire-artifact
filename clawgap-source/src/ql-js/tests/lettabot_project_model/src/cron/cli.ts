import { readFileSync, writeFileSync } from 'node:fs';

function loadStore() { return readFileSync('/tmp/cron'); }
function saveStore(store: string) { writeFileSync('/tmp/cron', store); }

export function run() { saveStore(String(loadStore())); }
