"use client";

import type React from "react";
import { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Send, Bot, User, AlertTriangle } from "lucide-react";
import { apiPostJson } from "@/lib/api";

interface Message {
  role: "user" | "assistant" | "error";
  content: string;
}

export default function RagChat() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content:
        "Hello! I'm your RAG Assistant. Ask me about packets, attack types, or security analysis and I'll query the system for you.",
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const sessionIdRef = useRef<string>("sess_" + Math.random().toString(36).slice(2));

  /* ---------- UX: scroll to latest ---------- */
  const scrollToBottom = () => messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  useEffect(() => { scrollToBottom(); }, [messages]);

  /* ---------- Submit ---------- */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setInput("");
    setIsLoading(true);

    // user bubble
    setMessages((prev) => [...prev, { role: "user", content: userMessage }]);

    try {
      const data = await apiPostJson<any>("/ask", {
        question: userMessage,
        session_id: sessionIdRef.current,
      });

      let msg = "";
      if (data.error) {
        setMessages((prev) => [...prev, { role: "error", content: data.error }]);
        setIsLoading(false);
        return;
      }

      if (data.mode === "SQL") {
        msg = data.answer || "(no summary)";
        if (Array.isArray(data.rows) && data.rows.length) {
          const preview = data.rows.slice(0, 5);
          const cols = data.cols || Object.keys(preview[0] || {});
          const head = cols.join(" | ");
          const body = preview
            .map((r: any) => cols.map((c: string) => String(r[c] ?? "")).join(" | "))
            .join("\n");
          msg += `\n\n**Sample rows (up to 5):**\n\n${head}\n${"-".repeat(head.length)}\n${body}`;
        }
        
      } else {
        msg = data.answer || "(no answer)";
      }

      setMessages((prev) => [...prev, { role: "assistant", content: msg }]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        { role: "error", content: `Network error: ${err?.message || "Failed to fetch"}` },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  return (
    // No background/border here on purpose - the page-level Card provides the glow and glassmorphism.
    <div className="flex flex-col h-[600px]">
      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-2 sm:p-3 space-y-4">
        <ul className="space-y-4" role="list">
          {messages.map((message, index) => {
            const isUser = message.role === "user";
            const isError = message.role === "error";
            return (
              <li
                key={index}
                role="listitem"
                className={`flex ${isUser ? "justify-end" : "justify-start"}`}
              >
                <div
                  className={`flex items-start space-x-3 max-w-[85%] ${
                    isUser ? "flex-row-reverse space-x-reverse" : ""
                  }`}
                >
                  {/* Avatar */}
                  <div
                    className={`flex-shrink-0 w-9 h-9 rounded-full grid place-items-center
                      ${isError
                        ? "bg-yellow-400/10 border border-yellow-400/30"
                        : "bg-cyan-500/20 border border-cyan-500/30"
                      }`}
                  >
                    {isUser ? (
                      <User className="w-4.5 h-4.5 text-cyan-300" />
                    ) : isError ? (
                      <AlertTriangle className="w-5 h-5 text-yellow-300" />
                    ) : (
                      <Bot className="w-5 h-5 text-cyan-300" />
                    )}
                  </div>

                  {/* Bubble */}
                  <div
                    className={`rounded-xl px-4 py-3 whitespace-pre-wrap leading-relaxed
                      ${isError
                        ? "bg-[#0f1a2a] border border-yellow-400/30 text-yellow-100"
                        : isUser
                        ? "bg-cyan-500/10 border border-cyan-400/30 text-cyan-50"
                        : "bg-white/5 border border-white/10 text-gray-100 shadow-[0_0_20px_rgba(34,211,238,.15)]"
                      }`}
                  >
                    <p className="text-sm">{message.content}</p>
                  </div>
                </div>
              </li>
            );
          })}

          {/* Typing indicator */}
          {isLoading && (
            <li role="listitem" className="flex justify-start">
              <div className="flex items-start space-x-3 max-w-[80%]">
                <div className="flex-shrink-0 w-9 h-9 rounded-full grid place-items-center bg-cyan-500/20 border border-cyan-500/30">
                  <Bot className="w-5 h-5 text-cyan-300" />
                </div>
                <div className="bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-gray-100">
                  <span className="inline-block animate-pulse">…Sending</span>
                </div>
              </div>
            </li>
          )}
        </ul>
        <div ref={messagesEndRef} />
      </div>

      {/* Input Bar */}
      <div className="pt-2">
        <form onSubmit={handleSubmit} className="flex gap-2">
          <Input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about network security, attack patterns, or get recommendations..."
            disabled={isLoading}
            className="flex-1 bg-transparent border-white/10 text-white placeholder-slate-400
                       focus:border-cyan-500/50 focus:ring-cyan-500/20"
            aria-label="Chat message input"
          />
          <Button
            type="submit"
            disabled={!input.trim() || isLoading}
            className="bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/30
                       disabled:opacity-50 disabled:cursor-not-allowed"
            aria-label="Send message"
            title="Send"
          >
            <Send className="w-4 h-4" />
          </Button>
        </form>
      </div>
    </div>
  );
}
