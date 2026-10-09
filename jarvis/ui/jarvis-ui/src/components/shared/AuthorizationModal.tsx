"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { AuthorizationResult, PendingAuthorization } from "@/lib/types";

interface AuthorizationModalProps {
  authorizations: PendingAuthorization[];
  onSubmit: (id: string, pin: string) => Promise<AuthorizationResult>;
  onCancel: (id: string) => void;
}

// The PIN is typed here and nowhere else: not spoken, not sent over the chat
// socket, not kept in app state. It lives only in this input until submit.
export default function AuthorizationModal({ authorizations, onSubmit, onCancel }: AuthorizationModalProps) {
  const current = authorizations[0] ?? null;
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [locked, setLocked] = useState(false);
  const currentId = current?.id ?? null;

  const cancel = useCallback(() => {
    if (currentId) onCancel(currentId);
  }, [currentId, onCancel]);

  useEffect(() => {
    setError("");
    setLocked(false);
    if (inputRef.current) inputRef.current.value = "";
    inputRef.current?.focus();
  }, [currentId]);

  useEffect(() => {
    if (!currentId) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") cancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [currentId, cancel]);

  if (!current) return null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const input = inputRef.current;
    if (!input || busy || locked) return;
    const pin = input.value;
    input.value = "";
    setBusy(true);
    const result = await onSubmit(current.id, pin);
    setBusy(false);
    if (!result.ok) {
      setLocked(result.locked);
      setError(
        result.locked
          ? result.error
          : `${result.error || "Wrong PIN."}${result.attemptsLeft != null ? ` ${result.attemptsLeft} left.` : ""}`
      );
      input.focus();
    }
  };

  return (
    <div
      className="fixed inset-0 z-[110] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="authorize-title"
    >
      <form
        onSubmit={submit}
        autoComplete="off"
        className="relative w-full max-w-md overflow-hidden bg-jarvis-surface/95 backdrop-blur-xl border border-white/[0.08] rounded-2xl shadow-2xl p-6"
        style={{ boxShadow: "0 8px 40px rgba(248,113,113,0.18), 0 2px 8px rgba(0,0,0,0.4)" }}
      >
        <div className="flex items-center gap-2 mb-3">
          <span className="text-3xs font-medium uppercase tracking-[0.14em] text-red-400">PIN required</span>
          <span className="text-3xs font-mono text-jarvis-text-dim/50 uppercase tracking-wider">authorization</span>
        </div>

        <h2 id="authorize-title" className="text-sm font-medium text-jarvis-text mb-2">
          Enter your PIN to allow this action
        </h2>
        <p className="text-xs text-jarvis-text/70 leading-relaxed mb-1 font-mono break-words">{current.tool}</p>
        <p className="text-xs text-jarvis-text-dim/70 leading-relaxed mb-4 break-all">{current.summary}</p>

        <input
          ref={inputRef}
          type="password"
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={8}
          autoComplete="off"
          autoCorrect="off"
          spellCheck={false}
          disabled={busy || locked}
          aria-label="Authorization PIN"
          className="w-full mb-2 px-3 py-2.5 rounded-lg text-sm tracking-[0.4em] text-jarvis-text bg-white/[0.05] border border-white/[0.08] focus:outline-none focus:ring-2 focus:ring-jarvis-cyan/40"
        />
        <p className="min-h-[1rem] mb-4 text-3xs text-red-400" role="alert">
          {error}
        </p>

        <div className="flex gap-2.5">
          <button
            type="submit"
            disabled={busy || locked}
            className="flex-1 py-2.5 rounded-lg text-xs font-medium text-jarvis-bg bg-jarvis-cyan hover:bg-jarvis-cyan/90 transition-colors disabled:opacity-40 focus:outline-none focus:ring-2 focus:ring-jarvis-cyan/40"
          >
            Authorize
          </button>
          <button
            type="button"
            onClick={cancel}
            className="flex-1 py-2.5 rounded-lg text-xs font-medium text-jarvis-text/80 bg-white/[0.05] hover:bg-white/[0.08] border border-white/[0.06] transition-colors focus:outline-none focus:ring-2 focus:ring-white/10"
          >
            Cancel
          </button>
        </div>

        {authorizations.length > 1 && (
          <p className="mt-3 text-3xs text-jarvis-text-dim/40 text-center">
            {authorizations.length - 1} more pending
          </p>
        )}
      </form>
    </div>
  );
}
