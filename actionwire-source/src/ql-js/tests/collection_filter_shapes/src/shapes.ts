declare function consume(value: unknown): void;

export function guardedAdmission(input: string) {
  const admitted: string[] = [];
  if (input.startsWith("safe:")) {
    admitted.push(input.trim());
  }
  consume(admitted);
}

export function rejectThenAdmit(input: string) {
  const admitted = new Set<string>();
  if (!input.startsWith("safe:")) {
    return;
  }
  admitted.add(input.trim());
  consume(admitted);
}

export function rejectContinueThenAdmit(input: string[]) {
  const admitted = new Map<string, string>();
  for (const item of input) {
    if (!item.startsWith("safe:")) {
      continue;
    }
    admitted.set(item, item.trim());
  }
  consume(admitted);
}

export function arrayFilterResult(input: string[]) {
  const admitted = input.filter((item) => item.startsWith("safe:"));
  consume(admitted);
}

export function unrelatedCollections(input: string, output: string[]) {
  const config: string[] = [];
  if (input.startsWith("safe:")) {
    config.push("fixed-config");
    output.push("formatted-output");
  }
  consume(config);
  consume(output);
}
