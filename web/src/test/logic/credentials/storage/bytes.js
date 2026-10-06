import { base64ToBytes, base64UrlToBytes } from '@/logic/shared/base64.js';

export function bytesOf(value) {
  return Array.from(value.includes('-') || value.includes('_') || !/[+/=]/.test(value)
    ? base64UrlToBytes(value)
    : base64ToBytes(value));
}
