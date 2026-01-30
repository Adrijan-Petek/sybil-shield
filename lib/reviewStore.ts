export type ReviewDecision = 'confirm_sybil' | 'dismiss' | 'escalate';

export type ActorReview = {
  actor: string;
  decision: ReviewDecision;
  note?: string;
  updatedAt: string; // ISO
};

const DB_NAME = 'sybil-shield';
const DB_VERSION = 1;
const STORE = 'actorReviews';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: 'actor' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function withStore<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const store = tx.objectStore(STORE);
        const req = fn(store);
        req.onsuccess = () => resolve(req.result as T);
        req.onerror = () => reject(req.error);
      }),
  );
}

export async function getAllReviews(): Promise<ActorReview[]> {
  return withStore<ActorReview[]>('readonly', (store) => store.getAll());
}

export async function getReview(actor: string): Promise<ActorReview | undefined> {
  return withStore<ActorReview | undefined>('readonly', (store) => store.get(actor));
}

export async function upsertReview(review: ActorReview): Promise<void> {
  await withStore<IDBValidKey>('readwrite', (store) => store.put(review));
}

export async function deleteReview(actor: string): Promise<void> {
  await withStore<undefined>('readwrite', (store) => store.delete(actor));
}
