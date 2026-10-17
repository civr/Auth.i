import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';

export class OidcProviderHolder {
  #provider: Provider | undefined;
  #handler: ((req: IncomingMessage, res: ServerResponse) => unknown) | undefined;

  constructor(private readonly factory: () => Promise<Provider>) {}

  async load(): Promise<void> {
    const provider = await this.factory();
    this.#provider = provider;
    this.#handler = provider.callback();
  }

  get provider(): Provider {
    if (!this.#provider) throw new Error('OIDC provider not loaded; call startServices() first');
    return this.#provider;
  }

  handle(req: IncomingMessage, res: ServerResponse): void {
    if (!this.#handler) throw new Error('OIDC provider not loaded; call startServices() first');
    void this.#handler(req, res);
  }
}
