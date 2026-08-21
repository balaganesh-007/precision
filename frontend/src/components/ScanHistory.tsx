import React from 'react';
import type { ScanHistoryItem } from '../types';

interface ScanHistoryProps {
  scans: ScanHistoryItem[];
  onSelectScan: (scanId: number) => void;
  loading: boolean;
  onRefresh: () => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({ scans, onSelectScan, loading, onRefresh }) => {
  
  const getStatusBadgeStyle = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return { color: 'var(--accent-green)', background: 'rgba(0, 230, 118, 0.1)', border: '1px solid rgba(0, 230, 118, 0.3)' };
      case 'RUNNING':
        return { color: 'var(--accent-cyan)', background: 'rgba(0, 240, 255, 0.1)', border: '1px solid rgba(0, 240, 255, 0.3)' };
      case 'PENDING':
        return { color: 'var(--text-secondary)', background: 'rgba(139, 155, 180, 0.1)', border: '1px solid rgba(139, 155, 180, 0.3)' };
      case 'FAILED':
        return { color: 'var(--accent-red)', background: 'rgba(255, 23, 68, 0.1)', border: '1px solid rgba(255, 23, 68, 0.3)' };
      default:
        return {};
    }
  };

  const getRiskBadgeStyle = (classification: string | null) => {
    if (!classification) return { color: 'var(--text-muted)', background: 'transparent' };
    switch (classification) {
      case 'CLEAN':
        return { color: 'var(--accent-green)', background: 'rgba(0, 230, 118, 0.15)', padding: '4px 8px', borderRadius: '4px', fontWeight: 'bold' };
      case 'SUSPICIOUS':
        return { color: 'var(--accent-orange)', background: 'rgba(255, 145, 0, 0.15)', padding: '4px 8px', borderRadius: '4px', fontWeight: 'bold' };
      case 'HIGH RISK':
        return { color: 'var(--accent-red)', background: 'rgba(255, 23, 68, 0.15)', padding: '4px 8px', borderRadius: '4px', fontWeight: 'bold' };
      default:
        return {};
    }
  };

  const formatSize = (bytes: number) => {
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  return (
    <div className="cyber-card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={{ color: 'var(--accent-cyan)' }} className="glow-text-cyan">[ HISTORICAL SCAN AUDITS ]</h3>
        <button className="btn-cyber" style={{ padding: '6px 12px', fontSize: '12px' }} onClick={onRefresh} disabled={loading}>
          {loading ? 'RELOADING...' : 'REFRESH LIST'}
        </button>
      </div>

      {loading && scans.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }} className="mono">
          QUERYING DATABASE RADAR SYSTEMS...
        </div>
      ) : scans.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }} className="mono">
          NO HISTORICAL DATA FOUND. UPLOAD A TARGET MODEL TO INITIATE COLD SCAN.
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', minWidth: '600px' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border-cyber)', color: 'var(--accent-cyan)' }} className="mono">
                <th style={{ padding: '12px' }}>TARGET MODEL</th>
                <th style={{ padding: '12px' }}>FORMAT</th>
                <th style={{ padding: '12px' }}>SIZE</th>
                <th style={{ padding: '12px' }}>TIMESTAMP</th>
                <th style={{ padding: '12px' }}>STATUS</th>
                <th style={{ padding: '12px' }}>RISK SCORE</th>
                <th style={{ padding: '12px' }}>RATING</th>
                <th style={{ padding: '12px', textAlign: 'right' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr 
                  key={scan.id} 
                  style={{ borderBottom: '1px solid var(--border-muted)', transition: 'var(--transition-smooth)' }}
                  className="scan-row"
                >
                  <td style={{ padding: '12px', fontWeight: '500', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {scan.model.name}
                  </td>
                  <td style={{ padding: '12px' }} className="mono">{scan.model.format}</td>
                  <td style={{ padding: '12px' }} className="mono">{formatSize(scan.model.file_size)}</td>
                  <td style={{ padding: '12px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                    {formatDate(scan.started_at)}
                  </td>
                  <td style={{ padding: '12px' }}>
                    <span 
                      style={{ 
                        padding: '4px 8px', 
                        borderRadius: '4px', 
                        fontSize: '11px', 
                        fontWeight: 'bold',
                        ...getStatusBadgeStyle(scan.status) 
                      }}
                      className="mono"
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td style={{ padding: '12px', fontWeight: 'bold' }} className="mono">
                    {scan.risk_score !== null ? `${scan.risk_score}/100` : '—'}
                  </td>
                  <td style={{ padding: '12px' }}>
                    {scan.risk_classification ? (
                      <span style={getRiskBadgeStyle(scan.risk_classification)}>
                        {scan.risk_classification}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>—</span>
                    )}
                  </td>
                  <td style={{ padding: '12px', textAlign: 'right' }}>
                    <button 
                      className="btn-cyber" 
                      style={{ padding: '4px 10px', fontSize: '11px' }}
                      onClick={() => onSelectScan(scan.id)}
                    >
                      VIEW AUDIT
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
