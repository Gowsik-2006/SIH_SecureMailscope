import {
  CaseRecord,
  SessionMetadata,
  Finding,
  Anomaly,
  RiskAssessment,
  AuditRecord,
  UserProfile,
  ActiveScanRequest,
  ActiveScanResult,
  CollectorConfig,
} from '../../shared/types.ts';

const API_BASE = '/api';

export class ApiClient {
  private static token: string | null = null;

  public static setToken(token: string | null) {
    this.token = token;
  }

  private static async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (!res.ok) {
      let errorMsg = `HTTP Error ${res.status}`;
      try {
        const text = await res.text();
        try {
          const errorJson = JSON.parse(text);
          if (errorJson.error && errorJson.error.message) {
            errorMsg = errorJson.error.message;
          }
        } catch {
          if (res.status === 404) {
            errorMsg = 'Backend API endpoint not found (404). Ensure Vercel serverless function or backend server is running.';
          } else if (text && text.length < 150) {
            errorMsg = text;
          }
        }
      } catch {
        // ignore
      }
      throw new Error(errorMsg);
    }

    const json = await res.json();
    return json.data as T;
  }

  public static async getHealth() {
    return this.request<any>('/health');
  }

  public static async login(username: string, password: string): Promise<{ token: string; profile: UserProfile }> {
    return this.request<{ token: string; profile: UserProfile }>('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
  }

  public static async getMe(): Promise<UserProfile> {
    return this.request<UserProfile>('/auth/me');
  }

  public static async getCases(): Promise<{ cases: CaseRecord[]; activeCaseId: string | null }> {
    return this.request<{ cases: CaseRecord[]; activeCaseId: string | null }>('/cases');
  }

  public static async getCase(id: string): Promise<{ record: CaseRecord; summary: any; riskAssessment: RiskAssessment }> {
    return this.request<{ record: CaseRecord; summary: any; riskAssessment: RiskAssessment }>(`/cases/${id}`);
  }

  public static async activateCase(id: string): Promise<{ activeCaseId: string }> {
    return this.request<{ activeCaseId: string }>(`/cases/${id}/activate`, { method: 'POST' });
  }

  public static async deleteCase(id: string): Promise<{ deleted: boolean }> {
    return this.request<{ deleted: boolean }>(`/cases/${id}`, { method: 'DELETE' });
  }

  private static async bytesToBase64(bytes: Uint8Array): Promise<string> {
    if (typeof FileReader !== 'undefined') {
      return new Promise<string>((resolve, reject) => {
        const blob = new Blob([bytes as any]);
        const reader = new FileReader();
        reader.onload = () => {
          const res = reader.result as string;
          const commaIdx = res.indexOf(',');
          resolve(commaIdx !== -1 ? res.slice(commaIdx + 1) : res);
        };
        reader.onerror = reject;
        reader.readAsDataURL(blob);
      });
    }

    // Fallback if FileReader unavailable
    let binary = '';
    const len = bytes.byteLength;
    const chunkSize = 8192;
    for (let i = 0; i < len; i += chunkSize) {
      const chunk = bytes.subarray(i, Math.min(i + chunkSize, len));
      binary += String.fromCharCode.apply(null, Array.from(chunk));
    }
    return btoa(binary);
  }

  public static async uploadPcap(buffer: Uint8Array, filename: string): Promise<{ jobId: string; case: CaseRecord }> {
    const base64Data = await this.bytesToBase64(buffer);
    return this.request<{ jobId: string; case: CaseRecord }>('/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ base64Data, filename }),
    });
  }

  public static async getSessions(protocol?: string, verdict?: string): Promise<SessionMetadata[]> {
    const params = new URLSearchParams();
    if (protocol) params.set('protocol', protocol);
    if (verdict) params.set('verdict', verdict);
    const query = params.toString() ? `?${params.toString()}` : '';
    return this.request<SessionMetadata[]>(`/sessions${query}`);
  }

  public static async getSession(id: string): Promise<SessionMetadata> {
    return this.request<SessionMetadata>(`/sessions/${id}`);
  }

  public static async getFindings(severity?: string, category?: string, sessionId?: string): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    if (category) params.set('category', category);
    if (sessionId) params.set('sessionId', sessionId);
    const query = params.toString() ? `?${params.toString()}` : '';
    return this.request<Finding[]>(`/findings${query}`);
  }

  public static async getCertificates(): Promise<any[]> {
    return this.request<any[]>('/certificates');
  }

  public static async getAnomalies(): Promise<Anomaly[]> {
    return this.request<Anomaly[]>('/anomalies');
  }

  public static async evaluateAi(): Promise<RiskAssessment> {
    return this.request<RiskAssessment>('/ai/evaluate', { method: 'POST' });
  }

  public static async generateDemo(): Promise<{ jobId: string; case: CaseRecord }> {
    return this.request<{ jobId: string; case: CaseRecord }>('/cases/load-trace', { method: 'POST' });
  }

  public static async loadIncidentTrace(): Promise<{ jobId: string; case: CaseRecord }> {
    return this.request<{ jobId: string; case: CaseRecord }>('/cases/load-trace', { method: 'POST' });
  }

  public static async scanMailServer(req: ActiveScanRequest): Promise<ActiveScanResult> {
    return this.request<ActiveScanResult>('/scan/mail-server', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
  }

  public static async getCollectorConfig(): Promise<CollectorConfig> {
    return this.request<CollectorConfig>('/collector/config');
  }

  public static async getAudit(): Promise<{ records: AuditRecord[]; verification: { valid: boolean; message: string } }> {
    return this.request<{ records: AuditRecord[]; verification: { valid: boolean; message: string } }>('/audit');
  }

  public static async verifyAudit(): Promise<{ valid: boolean; message: string }> {
    return this.request<{ valid: boolean; message: string }>('/audit/verify');
  }

  public static async getRules(): Promise<any[]> {
    return this.request<any[]>('/settings/rules');
  }

  public static async toggleRule(ruleId: string): Promise<any> {
    return this.request<any>(`/settings/rules/${ruleId}/toggle`, { method: 'POST' });
  }
}
