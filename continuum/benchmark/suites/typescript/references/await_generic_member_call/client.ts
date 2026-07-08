export class Client {
  m<T>(value: T): T {
    return value;
  }

  async run(): Promise<number> {
    return await this.m<number>(1);
  }
}
