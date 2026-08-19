import type { ServerResponse } from 'node:http';

/** Write a JSON HTTP response without coupling callers to a feature module. */
export function jsonRes(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}
