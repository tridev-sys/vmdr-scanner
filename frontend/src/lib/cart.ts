// Scanner cart: targets collected on the Targets page and scanned together from the Overview page.
// Persisted in localStorage; every storage access is guarded and falls back to an in-memory cart.
import { useSyncExternalStore } from "react";

export interface CartItem {
  id: number;
  url: string;
  host: string;
}

export const CART_STORAGE_KEY = "vmdr.scanCart";
const CART_EVENT = "vmdr-cart-change";

function isCartItem(v: unknown): v is CartItem {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return typeof o.id === "number" && typeof o.url === "string" && typeof o.host === "string";
}

function loadCart(): CartItem[] {
  try {
    const raw = window.localStorage.getItem(CART_STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter(isCartItem) : [];
  } catch {
    return [];
  }
}

// The in-memory copy is the source of truth for this tab; storage is a best-effort mirror.
let cart: CartItem[] = loadCart();

function persist(next: CartItem[]): void {
  try {
    window.localStorage.setItem(CART_STORAGE_KEY, JSON.stringify(next));
  } catch {
    /* storage unavailable (private mode, quota): the cart lives in memory only */
  }
}

function commit(next: CartItem[]): void {
  cart = next;
  persist(next);
  window.dispatchEvent(new Event(CART_EVENT));
}

export function getCart(): CartItem[] {
  return cart;
}

export function isInCart(id: number): boolean {
  return cart.some((item) => item.id === id);
}

export function addToCart(item: CartItem): void {
  if (isInCart(item.id)) return;
  commit([...cart, { id: item.id, url: item.url, host: item.host }]);
}

export function removeFromCart(id: number): void {
  if (!isInCart(id)) return;
  commit(cart.filter((item) => item.id !== id));
}

export function clearCart(): void {
  if (cart.length === 0) return;
  commit([]);
}

/** Calls `listener` whenever the cart changes. Returns the unsubscribe function. */
export function subscribeCart(listener: () => void): () => void {
  window.addEventListener(CART_EVENT, listener);
  return () => window.removeEventListener(CART_EVENT, listener);
}

/** Current cart; re-renders the component when it changes. */
export function useCart(): CartItem[] {
  return useSyncExternalStore(subscribeCart, getCart, getCart);
}
