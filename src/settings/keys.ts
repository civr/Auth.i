export const SETTING_KEYS = ['issuerUrl', 'cookieDomain', 'trustProxy', 'logLevel'] as const;
export type SettingKey = (typeof SETTING_KEYS)[number];

export const SETTING_ENV: Record<SettingKey, string> = {
  issuerUrl: 'KEYSTONE_ISSUER_URL',
  cookieDomain: 'KEYSTONE_COOKIE_DOMAIN',
  trustProxy: 'KEYSTONE_TRUST_PROXY',
  logLevel: 'LOG_LEVEL',
};

export const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
