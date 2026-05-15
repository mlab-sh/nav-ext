/**
 * Normalize defanged IOCs commonly found in threat-intel reports.
 * evil[.]com → evil.com, hxxp:// → http://, 1.1.1[.]1 → 1.1.1.1, [at] → @
 */
export function refang(text: string): string {
  return text
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/g, '.')
    .replace(/\[\s*:\s*\]|\(\s*:\s*\)/g, ':')
    .replace(/\[\s*@\s*\]|\(\s*@\s*\)|\[\s*at\s*\]|\(\s*at\s*\)/gi, '@')
    .replace(/\bhxxps:\/\//gi, 'https://')
    .replace(/\bhxxp:\/\//gi, 'http://')
    .replace(/\bfxp:\/\//gi, 'ftp://');
}
