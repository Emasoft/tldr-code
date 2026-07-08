export async function run(): Promise<string> {
  const mod = await import("./plugin");
  return mod.activate();
}
