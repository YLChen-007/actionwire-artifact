export class PermissionManager {
  private askHandler = async (_prompt: string): Promise<string> => 'no';

  async checkShellCommand(command: string): Promise<{ allowed: boolean }> {
    const trimmed = command.trim();
    if (trimmed === 'pwd') return { allowed: true };
    const result = await this.askHandler(`Run command: ${trimmed}`);
    return { allowed: result === 'yes' };
  }
}
