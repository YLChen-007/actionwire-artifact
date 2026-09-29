export async function execute(args: unknown) {
  const page: any = {};
  const client: any = {};
  await page.run(args);
  await client.send("Wrong.action", { value: args });
  await fetch(String(args));
}
