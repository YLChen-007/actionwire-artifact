import * as fs from 'node:fs';

export function copyByApiSignature(source: string, destination: string) {
  fs.copyFileSync(source, destination);
  const ordinaryObject = { copyFileSync(_source: string, _destination: string) {} };
  ordinaryObject.copyFileSync(source, destination);
}
