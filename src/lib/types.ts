export type IocType = 'domain' | 'ipv4' | 'ipv6';

export interface Ioc {
  type: IocType;
  value: string;
}

export interface DetectedIoc extends Ioc {
  /** raw text as it appeared on the page (possibly defanged) */
  raw: string;
  /** true if private/reserved IP — display only, no lookup offered */
  reserved?: boolean;
}

export type Verdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';

export interface ScanResult {
  ioc: Ioc;
  verdict: Verdict;
  /** raw response from mlab.sh API */
  data: unknown;
  fetchedAt: number;
  reportUrl?: string;
}

export interface Limits {
  domain?: { remaining: number; limit: number };
  ip?: { remaining: number; limit: number };
}

export type Msg =
  | { kind: 'detected'; iocs: DetectedIoc[]; href: string }
  | { kind: 'scan'; ioc: Ioc }
  | { kind: 'scan-result'; result: ScanResult }
  | { kind: 'get-cached'; ioc: Ioc }
  | { kind: 'cached-result'; result: ScanResult | null }
  | { kind: 'get-limits' }
  | { kind: 'limits'; limits: Limits }
  | { kind: 'get-tab-iocs' }
  | { kind: 'tab-iocs'; iocs: DetectedIoc[] }
  | { kind: 'set-api-key'; key: string }
  | { kind: 'api-key-ok'; ok: boolean; error?: string }
  | { kind: 'has-api-key' }
  | { kind: 'has-api-key-result'; present: boolean }
  | { kind: 'get-history' }
  | { kind: 'history'; entries: ScanResult[] }
  | { kind: 'clear-history' };
