import { Card, CardContent } from "@/components/ui/card";
import { Bot, Brain } from "lucide-react";
import RagChat from "@/components/RagChat";

export default function RAGSystemPage() {
  return (
    <div className="min-h-screen p-6">
      <div className="max-w-3xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="relative">
              <div className="w-16 h-16 rounded-full bg-gradient-to-br from-cyan-500/20 to-blue-500/20 flex items-center justify-center cyber-glow-blue">
                <Bot className="w-8 h-8 text-cyan-400" />
              </div>
              <div className="absolute -top-1 -right-1 w-5 h-5 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-full flex items-center justify-center">
                <Brain className="w-2.5 h-2.5 text-white" />
              </div>
            </div>
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">RAG Assistant</h1>
            <p className="text-gray-300">
              Intelligent security assistant powered by Retrieval-Augmented Generation
            </p>
          </div>
        </div>

        {/* Chat Interface */}
        <Card className="glassmorphism border-cyan-500/20 cyber-glow">
          <CardContent className="p-6">
            <RagChat />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
