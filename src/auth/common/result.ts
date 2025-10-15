export type Ok<T> = { ok: true; data: T };
export type Err = { ok: false; code: string; message: string };
export type Result<T> = Ok<T> | Err;

export const ok = <T>(data: T): Ok<T> => ({ ok: true, data });
export const err = (code: string, message: string): Err => ({ ok: false, code, message });
