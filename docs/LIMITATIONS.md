# SIH26159 Environment Limitations & Boundary Notes

## 1. Raw Promiscuous Socket Permissions (Live Capture)
- **Constraint:** In sandboxed container environments without `CAP_NET_RAW` / `CAP_NET_ADMIN` Linux capabilities, raw network socket capture cannot attach directly to physical promiscuous interfaces.
- **Handling:** The Live Capture panel enlists real system network interfaces (`os.networkInterfaces()`), enforces strict BPF filter validation, checks interface existence without executing shell commands, and operates in passive simulation mode when raw packet sniffing privileges are denied by the kernel sandbox.

## 2. Gemini API Key Availability
- **Constraint:** When `GEMINI_API_KEY` is not supplied by the environment or secrets panel, cloud LLM inference is unreachable.
- **Handling:** The platform incorporates an enterprise-grade Deterministic Fallback Engine (`server/ai/deterministic-fallback.ts`). It generates exact, traceably grounded risk reasoning, impact statements, and remediation action plans derived deterministically from the rule engine and ground-truth PCAP extraction.

## 3. Large File Streaming Thresholds
- **Constraint:** Upload payloads over HTTP are limited to 50 MB to prevent worker thread exhaustion and buffer overflow inside browser and node memory heaps.
- **Handling:** Streaming chunk inspection and early length bounds guard against memory denial of service.
