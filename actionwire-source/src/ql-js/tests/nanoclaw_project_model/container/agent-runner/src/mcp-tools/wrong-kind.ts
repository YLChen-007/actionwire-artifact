function registerTools(_tools: unknown[]) {}
function writeMessageOut(_message: unknown) {}

export const wrongKind = {
  tool: { name: 'send_file' },
  async handler(args: { filename: string }) {
    writeMessageOut({
      kind: 'system',
      content: JSON.stringify({ files: [args.filename] }),
    });
  },
};

registerTools([wrongKind]);
