export interface Model {
  id: number;
  name: string;
  format: string;
  file_size: number;
  sha256_hash: string;
  created_at: string;
}

export interface Finding {
  id: number;
  scan_id: number;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  module: 'FORMAT' | 'WEIGHTS' | 'STEGO' | 'BEHAVIOR';
  title: string;
  description: string;
  layer_name: string | null;
  evidence: any;
  created_at: string;
}

export interface Report {
  id: number;
  scan_id: number;
  report_path: string | null;
  created_at: string;
}

export interface Scan {
  id: number;
  model_id: number;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  risk_score: number | null;
  risk_classification: 'CLEAN' | 'SUSPICIOUS' | 'HIGH RISK' | null;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
}

export interface ScanHistoryItem extends Scan {
  model: Model;
}

export interface ScanDetail extends Scan {
  model: Model;
  findings: Finding[];
  reports: Report[];
}

export interface UploadResponse {
  model: Model;
  message: string;
}
