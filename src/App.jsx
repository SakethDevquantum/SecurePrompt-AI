import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Cpu, 
  Send, 
  CheckCircle, 
  Terminal, 
  RefreshCw, 
  X,
  Play,
  ArrowRight,
  User,
  Info,
  Server,
  Lock,
  MessageSquare
} from 'lucide-react';
import { deploymentData } from './architectureData';

const BACKEND_URL = "http://127.0.0.1:8000";

export default function App() {
  const [activeTab, setActiveTab] = useState('chat'); // 'chat' | 'deployment'
  const [inputText, setInputText] = useState("");
  const [availableModels, setAvailableModels] = useState(["phi4-mini:latest", "llama2-uncensored:7b", "llama3.1:latest"]);
  const [selectedModel, setSelectedModel] = useState("phi4-mini:latest");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isRewriting, setIsRewriting] = useState(false);
  
  // Real-time API scan output
  const [scanResult, setScanResult] = useState(null);
  
  // Modals state
  const [showWarningModal, setShowWarningModal] = useState(false);
  const [showFinalWarning, setShowFinalWarning] = useState(false);
  const [showRewriteComparison, setShowRewriteComparison] = useState(false);
  
  // Re-write result
  const [rewrittenPrompt, setRewrittenPrompt] = useState("");
  const [rewriteModelUsed, setRewriteModelUsed] = useState("");

  // Activity Log
  const addLog = () => {};

  // Fetch installed Ollama models on mount
  useEffect(() => {
    fetch(`${BACKEND_URL}/models`)
      .then(res => {
        if (res.ok) {
          addLog("GET /models HTTP/1.1 200 OK", "response");
        }
        return res.json();
      })
      .then(data => {
        if (data && data.models && data.models.length > 0) {
          setAvailableModels(data.models);
          setSelectedModel(data.models[0]);
        }
      })
      .catch(err => console.warn("Failed to load local models:", err));
  }, []);
  
  // Simulated chat messages
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content: "Hello! I am a simulated public AI assistant (e.g. ChatGPT / Claude). Enter a prompt below, and the SecurePrompt Extension gateway will intercept it in real time, evaluate data leak risks, and help you sanitize any sensitive corporate assets before submission."
    }
  ]);



  // Sample templates for testing
  const sampleTemplates = [
    {
      label: "Financial leak",
      text: "Summarize this request for client Saketh: email is saketh@company.com, account is 12345-67890, and monthly base salary is $15,000."
    },
    {
      label: "Credentials leak",
      text: "Fix my database auth code. It is for Project Apollo on https://internal-apollo.dev.corp/v1 and uses api_key='apikey_live_55a9bc8d4'."
    },
    {
      label: "Safe coding query",
      text: "How do I build a debounce custom hook in React?"
    }
  ];

  // 1. Scan/Analyze Prompt
  const handleAnalyzePrompt = async (e) => {
    if (e) e.preventDefault();
    if (!inputText.trim()) return;

    setIsAnalyzing(true);
    addLog(`Initiating prompt analysis payload...`, "request", { prompt: inputText });

    try {
      const response = await fetch(`${BACKEND_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: inputText })
      });

      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      addLog(`POST /analyze HTTP/1.1 200 OK`, "response");
      const data = await response.json();
      
      setScanResult(data);
      addLog(`Analysis complete. Risk Score: ${data.riskScore}/100. Detected entities: ${data.entities.length}`, "response", data);

      if (data.riskScore >= 40) {
        // Flagged! Show warning modal
        setShowWarningModal(true);
      } else {
        // Safe prompt, submit directly
        submitToChat(inputText, "clean");
      }
    } catch (error) {
      console.error(error);
      addLog(`Failed to communicate with FastAPI backend: ${error.message}. Is backend running on localhost:8000?`, "error");
      // Fallback local mockup analysis to keep application runnable
      runMockupAnalysis();
    } finally {
      setIsAnalyzing(false);
    }
  };

  const runMockupAnalysis = () => {
    const lowercase = inputText.toLowerCase();
    let score = 5;
    let level = "LOW RISK";
    let entities = [];
    let reason = "No major sensitive items detected. The prompt is safe to transmit.";

    if (lowercase.includes("saketh") || lowercase.includes("salary") || lowercase.includes("account")) {
      score = 88;
      level = "HIGH RISK";
      reason = "Prompt contains highly sensitive items such as email addresses, credentials, or internal subdomains.";
      entities = [
        { item: "Saketh", type: "PII Name", severity: "Medium", confidence: 0.95 },
        { item: "saketh@company.com", type: "PII Email", severity: "High", confidence: 0.95 },
        { item: "12345-67890", type: "Financial Account", severity: "High", confidence: 0.95 },
        { item: "$15,000", type: "Financial Salary", severity: "Medium", confidence: 0.85 }
      ];
    } else if (lowercase.includes("apollo") || lowercase.includes("api_key") || lowercase.includes(".corp")) {
      score = 95;
      level = "HIGH RISK";
      reason = "Prompt contains highly sensitive items such as email addresses, credentials, or internal subdomains.";
      entities = [
        { item: "Project Apollo", type: "Internal Project Name", severity: "Medium", confidence: 0.90 },
        { item: "https://internal-apollo.dev.corp/v1", type: "Internal URL", severity: "High", confidence: 0.90 },
        { item: "apikey_live_55a9bc8d4", type: "Credential API Key", severity: "High", confidence: 0.95 }
      ];
    }

    const data = { riskScore: score, riskLevel: level, reason, entities };
    setScanResult(data);
    addLog(`[Local Fallback Engine] Analysis complete. Risk Score: ${score}/100`, "response", data);
    
    if (score >= 40) {
      setShowWarningModal(true);
    } else {
      submitToChat(inputText, "clean");
    }
  };

  // 2. Request LLM Rewrite via FastAPI/Ollama
  const handleRequestRewrite = async () => {
    if (!inputText || !scanResult) return;

    setIsRewriting(true);
    addLog(`Querying LLM rewrite engine via FastAPI...`, "request", { 
      prompt: inputText, 
      entities: scanResult.entities,
      model: selectedModel 
    });

    try {
      const response = await fetch(`${BACKEND_URL}/rewrite`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          prompt: inputText, 
          entities: scanResult.entities,
          model: selectedModel
        })
      });

      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      addLog(`POST /rewrite HTTP/1.1 200 OK`, "response");
      const data = await response.json();
      
      setRewrittenPrompt(data.safePrompt);
      setRewriteModelUsed(data.modelUsed);
      addLog(`Rewrite success. Model: ${data.modelUsed}`, "response", data);
      
      setShowRewriteComparison(true);
    } catch (error) {
      console.error(error);
      addLog(`Failed to query rewrite backend: ${error.message}. Using deterministic fallback.`, "error");
      
      // Fallback deterministic rewrite
      let rewritten = inputText;
      scanResult.entities.forEach(ent => {
        rewritten = rewritten.replace(ent.item, `[${ent.type.toUpperCase()}]`);
      });
      setRewrittenPrompt(rewritten);
      setRewriteModelUsed("Fallback Deterministic Engine");
      setShowRewriteComparison(true);
    } finally {
      setIsRewriting(false);
    }
  };

  // 3. Submit Prompt to simulated chat
  const submitToChat = (text, flagType) => {
    let flagLabel = "";
    if (flagType === "clean") flagLabel = "✔ Sent Direct (Low Risk)";
    else if (flagType === "original") flagLabel = "⚠ Sent Original (Bypassed Warning)";
    else if (flagType === "safe") flagLabel = "✔ Sent Privacy-Safe (LLM Redacted)";

    // Add user message
    const userMsg = { role: "user", content: text, flag: flagLabel };
    
    // Create mock assistant response based on prompt contents
    let botReply = "I have received your prompt. ";
    if (text.includes("[") || text.includes("Redacted") || text.includes("Salary")) {
      botReply += "Thank you for sending the privacy-safe version. All sensitive variables have been redacted or generalized, preventing company data leakage while allowing me to answer your core request.";
    } else {
      botReply += "WARNING: This input contains raw names, credentials, or corporate network assets. In a real-world scenario, this raw data would now be indexed by a public chatbot model.";
    }

    const assistantMsg = { role: "assistant", content: botReply };

    setMessages(prev => [...prev, userMsg, assistantMsg]);
    setInputText("");
    setScanResult(null);
    setShowWarningModal(false);
    setShowFinalWarning(false);
    setShowRewriteComparison(false);
  };

  return (
    <div className="min-h-screen bg-[#080C14] text-slate-100 flex flex-col antialiased">
      {/* Header */}
      <header className="border-b border-[#1F2E47] bg-[#0E1624] px-6 py-4 sticky top-0 z-30">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-sky-950/80 border border-sky-500/30 rounded-xl text-sky-400">
              <Shield className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-white font-sans">SecurePrompt Security Gateway</h1>
                <span className="badge badge-success font-mono text-[10px]">Active</span>
              </div>
              <p className="text-xs text-slate-400">PII Redaction Engine & Ollama LLM Rewriter</p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            {/* Model Selector */}
            <div className="flex items-center gap-2 bg-[#080C14] border border-[#1F2E47] px-3 py-1.5 rounded-lg text-xs">
              <span className="text-slate-400">LLM Rewrite Model:</span>
              <select 
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="bg-transparent text-sky-400 border-none outline-none font-semibold cursor-pointer"
              >
                {availableModels.map(m => (
                  <option key={m} value={m} className="bg-[#0E1624] text-slate-100">{m}</option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </header>

      {/* Main Workspace */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 flex flex-col gap-6">
        
        {/* Chat Simulator Pane */}
        <div className="flex flex-col gap-4 w-full">
              <div className="card bg-[#0E1624] border-[#1F2E47] p-5 h-[580px] flex flex-col justify-between">
                
                {/* Simulated Chat Interface Header */}
                <div className="flex justify-between items-center border-b border-[#1F2E47]/70 pb-3 mb-4">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-red-500"></div>
                    <span className="text-xs font-bold text-slate-300 uppercase tracking-wide">Public AI Chatbot Interface (ChatGPT Mock)</span>
                  </div>
                  <span className="text-[10px] text-amber-500 font-mono flex items-center gap-1">
                    <Lock className="w-3.5 h-3.5" /> Extension Interceptor Active
                  </span>
                </div>

                {/* Messages Box */}
                <div className="flex-1 overflow-y-auto pr-2 space-y-4 text-xs">
                  {messages.map((msg, index) => (
                    <div 
                      key={index}
                      className={`p-3 rounded-xl max-w-[85%] ${msg.role === 'user' ? 'bg-sky-950/20 border border-sky-500/20 text-slate-100 ml-auto' : 'bg-[#080C14] border border-[#1F2E47] text-slate-300'}`}
                    >
                      <div className="flex justify-between items-center mb-1 text-[10px] font-semibold text-slate-400">
                        <span className="flex items-center gap-1">
                          {msg.role === 'user' ? <User className="w-3 h-3 text-sky-400" /> : <Cpu className="w-3 h-3 text-purple-400" />}
                          {msg.role === 'user' ? 'You' : 'Public AI'}
                        </span>
                        {msg.flag && (
                          <span className={`font-mono text-[9px] px-1.5 py-0.5 rounded ${msg.flag.includes('Original') ? 'bg-red-950/40 text-red-400 border border-red-500/20' : 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/20'}`}>
                            {msg.flag}
                          </span>
                        )}
                      </div>
                      <p className="leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                    </div>
                  ))}
                </div>

                {/* Input Text Form */}
                <form onSubmit={handleAnalyzePrompt} className="mt-4 pt-4 border-t border-[#1F2E47]/70 space-y-3">
                  {/* Preset quick prompt templates */}
                  <div className="flex flex-wrap gap-2">
                    <span className="text-[10px] text-slate-500 font-bold self-center">Samples:</span>
                    {sampleTemplates.map((tmpl, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => setInputText(tmpl.text)}
                        className="px-2.5 py-1 bg-[#080C14] border border-[#1F2E47] hover:border-slate-500 text-[10px] rounded-lg text-slate-400 hover:text-slate-200 transition-all"
                      >
                        {tmpl.label}
                      </button>
                    ))}
                  </div>

                  <div className="flex gap-2">
                    <input 
                      type="text"
                      value={inputText}
                      onChange={(e) => setInputText(e.target.value)}
                      placeholder="Paste your prompt containing client info, credentials or salaries here..."
                      className="flex-1 bg-[#080C14] border border-[#1F2E47] focus:border-sky-500 text-slate-100 px-4 py-3 rounded-xl text-xs outline-none transition-all placeholder-slate-600"
                    />
                    <button
                      type="submit"
                      disabled={isAnalyzing || !inputText.trim()}
                      className="px-5 bg-sky-600 hover:bg-sky-500 text-white rounded-xl text-xs font-semibold disabled:opacity-40 transition-all flex items-center gap-1.5 shrink-0"
                    >
                      {isAnalyzing ? (
                        <RefreshCw className="w-4.5 h-4.5 animate-spin" />
                      ) : (
                        <Send className="w-4.5 h-4.5" />
                      )}
                      Inspect
                    </button>
                  </div>
                </form>

              </div>
            </div>

      </main>

      {/* FOOTER */}
      <footer className="border-t border-[#1F2E47] bg-[#0E1624] px-6 py-4 text-center mt-auto text-xs text-slate-500">
        SecurePrompt AI Gateway Sandbox. Operates on Microsoft Presidio and Llama 3.1 / Phi-4-mini Local Inference.
      </footer>

      {/* MODAL 1: SECURITY WARNING POPUP (Derived from idealogy.jpg Section 8) */}
      {showWarningModal && scanResult && (
        <div className="fixed inset-0 bg-[#04060B]/85 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="card bg-[#0E1624] border-[#1F2E47] max-w-lg w-full overflow-hidden shadow-2xl relative">
            
            {/* Modal Header */}
            <div className="flex justify-between items-center border-b border-[#1F2E47]/70 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400 animate-pulse" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">SecurePrompt Warning UI</h3>
              </div>
              <button 
                onClick={() => setShowWarningModal(false)}
                className="text-slate-400 hover:text-slate-100"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="space-y-4">
              
              {/* Score and Reason */}
              <div className="flex gap-4 items-center p-3 bg-red-950/10 border border-red-500/20 rounded-xl">
                <div className="w-14 h-14 rounded-full border-2 border-red-500/50 flex items-center justify-center shrink-0">
                  <span className="text-md font-bold text-red-400 font-mono">{scanResult.riskScore}/100</span>
                </div>
                <div>
                  <h4 className="text-xs font-bold text-white uppercase">Overall Risk Level: {scanResult.riskLevel}</h4>
                  <p className="text-[11px] text-slate-400 leading-relaxed mt-0.5">{scanResult.reason}</p>
                </div>
              </div>

              {/* Detected Items */}
              <div className="space-y-1.5">
                <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Detected Sensitive Items</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-[140px] overflow-y-auto pr-1">
                  {scanResult.entities.map((ent, idx) => (
                    <div key={idx} className="p-2 bg-[#080C14] border border-[#1F2E47] rounded-lg text-xs flex justify-between items-center">
                      <span className="font-mono text-white truncate max-w-[120px]" title={ent.item}>{ent.item}</span>
                      <span className="badge badge-warning text-[9px] font-semibold">{ent.type}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Actions Grid */}
              <div className="space-y-2 pt-2 border-t border-[#1F2E47]/70">
                <button
                  onClick={handleRequestRewrite}
                  disabled={isRewriting}
                  className="w-full p-3 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs text-left flex justify-between items-center transition-all shadow-md"
                >
                  <div>
                    <span className="block font-bold">Choice A: Generate Safe Prompt (Recommended)</span>
                    <span className="text-[10px] text-sky-200">Rewrites context and redacts private variables using {selectedModel}</span>
                  </div>
                  {isRewriting ? (
                    <RefreshCw className="w-5 h-5 animate-spin text-white" />
                  ) : (
                    <ArrowRight className="w-5 h-5 text-white" />
                  )}
                </button>

                <button
                  onClick={() => setShowFinalWarning(true)}
                  className="w-full p-3 rounded-xl bg-red-950/20 border border-red-500/30 hover:border-red-500/70 text-red-400 hover:text-red-300 font-semibold text-xs text-left flex justify-between items-center transition-all"
                >
                  <div>
                    <span className="block font-bold">Choice B: Send Original Prompt</span>
                    <span className="text-[10px] text-red-400/70">Bypass corporate gateway and send raw prompt anyway</span>
                  </div>
                  <AlertTriangle className="w-5 h-5" />
                </button>

                <button
                  onClick={() => setShowWarningModal(false)}
                  className="w-full p-2.5 rounded-xl border border-slate-700 hover:border-slate-500 text-slate-400 hover:text-slate-200 text-xs font-semibold text-center transition-all"
                >
                  Cancel & Edit Prompt
                </button>
              </div>

            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: FINAL WARNING OVERLAY (Derived from idealogy.jpg Section 9B) */}
      {showFinalWarning && (
        <div className="fixed inset-0 bg-[#04060B]/90 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="card bg-[#0E1624] border-red-500/30 max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex gap-3">
              <AlertTriangle className="w-8 h-8 text-red-400 shrink-0 mt-0.5" />
              <div>
                <h3 className="font-bold text-white text-sm">9B. Final warning popup (If Original)</h3>
                <p className="text-xs text-slate-400 mt-1">
                  You are bypassing standard safety measures. This prompt will be transmitted unredacted to external public AI servers.
                </p>
              </div>
            </div>

            <div className="p-3 bg-[#080C14] border border-[#1F2E47] rounded-lg text-[11px] font-mono text-red-400">
              Score: {scanResult?.riskScore}/100. Severity Category: HIGH EXPOSURE risk.
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => setShowFinalWarning(false)}
                className="flex-1 py-2 rounded-lg text-xs font-semibold border border-slate-700 text-slate-300 hover:bg-slate-800 transition-all"
              >
                Go Back
              </button>
              <button
                onClick={() => submitToChat(inputText, "original")}
                className="flex-1 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 text-white transition-all"
              >
                Confirm & Transmit
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: REWRITE COMPARISON VIEW */}
      {showRewriteComparison && (
        <div className="fixed inset-0 bg-[#04060B]/85 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="card bg-[#0E1624] border-[#1F2E47] max-w-2xl w-full p-5 space-y-4 shadow-2xl">
            
            <div className="flex justify-between items-center border-b border-[#1F2E47]/70 pb-3">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-sky-400" />
                <div>
                  <h3 className="font-bold text-white text-sm">9A. Safe Prompt Review Sandbox</h3>
                  <p className="text-[10px] text-slate-400">Generated using {rewriteModelUsed}</p>
                </div>
              </div>
              <button 
                onClick={() => setShowRewriteComparison(false)}
                className="text-slate-400 hover:text-slate-100"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-3 bg-[#080C14] border border-[#1F2E47] rounded-xl space-y-1.5">
                <span className="text-[9px] text-red-400 font-bold uppercase tracking-wide">Original Prompt:</span>
                <div className="text-xs font-mono text-slate-300 max-h-[160px] overflow-y-auto whitespace-pre-wrap leading-relaxed">
                  {inputText}
                </div>
              </div>

              <div className="p-3 bg-sky-950/10 border border-sky-500/20 rounded-xl space-y-1.5">
                <span className="text-[9px] text-sky-400 font-bold uppercase tracking-wide">Privacy-Safe Prompt:</span>
                <div className="text-xs font-mono text-white max-h-[160px] overflow-y-auto whitespace-pre-wrap leading-relaxed">
                  {rewrittenPrompt}
                </div>
              </div>
            </div>

            <div className="p-3 bg-[#080C14] border border-[#1F2E47] rounded-lg text-[10px] text-slate-400">
              <strong>Sanitization Rules Applied:</strong> Preserved original instructions, generalised identified name/account elements, and omitted credential keys.
            </div>

            <div className="flex gap-2 justify-end pt-2 border-t border-[#1F2E47]/70">
              <button
                onClick={() => setShowRewriteComparison(false)}
                className="px-4 py-2 border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-slate-100 text-xs font-semibold rounded-lg transition-all"
              >
                Go Back
              </button>
              <button
                onClick={() => submitToChat(rewrittenPrompt, "safe")}
                className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold rounded-lg transition-all shadow-md"
              >
                Approve & Send Safe Prompt
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
