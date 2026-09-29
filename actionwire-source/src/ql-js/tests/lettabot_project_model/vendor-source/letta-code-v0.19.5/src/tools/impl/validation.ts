export function validateRequiredParams(
  args: object,
  required: string[],
  toolName: string,
): void {
  const missing = required.filter((key) => !(key in args));
  if (missing.length > 0) {
    throw new Error(`${toolName} missing ${missing.join(",")}`);
  }
}
