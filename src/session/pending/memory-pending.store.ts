import { PendingStore } from './pending.store';
import { PendingData } from '../session.types';

export class MemoryPendingStore extends PendingStore {
  private map = new Map<string, PendingData>();

  async set(state: string, data: PendingData) {
    this.map.set(state, data);
  }
  async take(state: string) {
    const d = this.map.get(state);
    if (d) this.map.delete(state);
    return d;
  }
  async gc() { /* noop en memoria */ }
}
