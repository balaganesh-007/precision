import type { UploadResponse, Scan, ScanHistoryItem, ScanDetail } from '../types';

const API_BASE_URL = 'http://localhost:8000/api';

export const api = {
  async uploadModel(file: File): Promise<UploadResponse> {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${API_BASE_URL}/models/upload`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: 'Unknown upload error' }));
      throw new Error(errorData.detail || 'Failed to upload model');
    }

    return response.json();
  },

  async startScan(modelId: number): Promise<Scan> {
    const response = await fetch(`${API_BASE_URL}/scans/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ model_id: modelId }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: 'Failed to start scan' }));
      throw new Error(errorData.detail || 'Failed to start scan');
    }

    return response.json();
  },

  async getScanHistory(): Promise<ScanHistoryItem[]> {
    const response = await fetch(`${API_BASE_URL}/scans`);
    if (!response.ok) {
      throw new Error('Failed to fetch scan history');
    }
    return response.json();
  },

  async getScanDetail(scanId: number): Promise<ScanDetail> {
    const response = await fetch(`${API_BASE_URL}/scans/${scanId}`);
    if (!response.ok) {
      throw new Error(`Failed to fetch scan details for Scan ID: ${scanId}`);
    }
    return response.json();
  },

  getReportDownloadUrl(scanId: number): string {
    return `${API_BASE_URL}/reports/${scanId}/download`;
  },

  async getHealth(): Promise<{ status: string; database_type: string }> {
    const response = await fetch(`${API_BASE_URL}/health`);
    if (!response.ok) {
      throw new Error('Backend health check failed');
    }
    return response.json();
  }
};
