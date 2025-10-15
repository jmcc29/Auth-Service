import { SessionStore } from './session.store';
import { SessionData } from '../session.types';

export class MemorySessionStore extends SessionStore {
  private map = new Map<string, { data: SessionData; exp?: number }>();

  async get(sid: string) {
    const e = this.map.get(sid);
    if (!e) return;
    if (e.exp && e.exp < Date.now()) { this.map.delete(sid); return; }
    return e.data;
  }
  async set(sid: string, data: SessionData, ttlMs?: number) {
    const exp = ttlMs ? Date.now() + ttlMs : undefined;
    this.map.set(sid, { data, exp });
  }
  async del(sid: string) { this.map.delete(sid); }
  async gc() {
    const now = Date.now();
    for (const [k,v] of this.map) if (v.exp && v.exp < now) this.map.delete(k);
  }
}
