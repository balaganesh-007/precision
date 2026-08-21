import React from 'react';
import type { ScanDetail } from '../types';
import { api } from '../services/api';

interface ScanResultProps {
  scanDetail: ScanDetail;
  onBack: () => void;
}

export const ScanResult: React.FC<ScanResultProps> = ({ scanDetail, onBack }) => {
  const { id, model, status, risk_score, risk_classification, started_at, completed_at, findings, error_message } = scanDetail;

  const handleDownloadReport = () => {
    const url = api.getReportDownloadUrl(id);
    window.open(url, '_blank');
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'var(--accent-red)';
    if (score >= 25) return 'var(--accent-orange)';
    return 'var(--accent-green)';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'var(--accent-red)';
      case 'HIGH': return 'var(--accent-red)';
      case 'MEDIUM': return 'var(--accent-orange)';
      case 'LOW': return 'var(--accent-cyan)';
      case 'INFO': return 'var(--text-secondary)';
      default: return 'var(--text-primary)';
    }
  };

  const formatBytes = (bytes: number) => {
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  };

  return (
    <div>
      {/* Back Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '20px' }}>
        <button 
          className="btn-cyber" 
          style={{ padding: '6px 16px', fontSize: '12px' }}
          onClick={onBack}
        >
          &lt; BACK TO DASHBOARD
        </button>
        <span className="mono" style={{ color: 'var(--text-muted)' }}>
          SCAN_SESSION_ID: #{id}
        </span>
      </div>

      {status === 'FAILED' ? (
        <div className="cyber-card" style={{ borderLeft: '4px solid var(--accent-red)' }}>
          <h3 style={{ color: 'var(--accent-red)', marginBottom: '8px' }}>[ SCAN EXECUTION FAILURE ]</h3>
          <p style={{ color: 'var(--text-primary)', marginBottom: '16px' }}>{error_message || 'An unexpected error halted the analysis.'}</p>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Started at: {new Date(started_at).toLocaleString()}
          </p>
        </div>
      ) : status !== 'COMPLETED' ? (
        <div className="cyber-card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div className="pulse" style={{ fontSize: '48px', color: 'var(--accent-cyan)', marginBottom: '16px' }}>🛰️</div>
          <h3 className="pulse glow-text-cyan" style={{ color: 'var(--accent-cyan)', marginBottom: '8px' }}>
            [ ANALYSIS IN PROGRESS... ]
          </h3>
          <p style={{ color: 'var(--text-secondary)' }}>
            Statically extracting weight tensors, validating opcodes, and evaluating Shannon entropy.
          </p>
          <div style={{
            width: '200px',
            height: '4px',
            background: 'var(--bg-tertiary)',
            margin: '24px auto 0',
            position: 'relative',
            overflow: 'hidden',
            borderRadius: '2px'
          }}>
            <div style={{
              width: '40%',
              height: '100%',
              background: 'var(--accent-cyan)',
              position: 'absolute',
              animation: 'slide-progress 1.5s infinite ease-in-out',
              borderRadius: '2px'
            }}></div>
          </div>
          <style>{`
            @keyframes slide-progress {
              0% { left: -40%; }
              50% { left: 100%; }
              100% { left: 100%; }
            }
          `}</style>
        </div>
      ) : (
        <div>
          {/* Top Panel: Summary & Metrics */}
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', 
            gap: '24px',
            marginBottom: '24px'
          }}>
            
            {/* Risk Badge & Dial */}
            <div className="cyber-card" style={{ 
              display: 'flex', 
              flexDirection: 'column', 
              alignItems: 'center', 
              justifyContent: 'center',
              textAlign: 'center',
              borderTop: `4px solid ${getScoreColor(risk_score ?? 0)}`
            }}>
              <span className="mono" style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
                AGGREGATE THREAT INDEX
              </span>
              
              {/* Circular Gauge Representation */}
              <div style={{
                position: 'relative',
                width: '160px',
                height: '160px',
                borderRadius: '50%',
                background: `conic-gradient(${getScoreColor(risk_score ?? 0)} ${(risk_score ?? 0) * 3.6}deg, var(--bg-tertiary) 0deg)`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: `0 0 20px ${getScoreColor(risk_score ?? 0)}20`,
                marginBottom: '16px'
              }}>
                <div style={{
                  width: '136px',
                  height: '136px',
                  borderRadius: '50%',
                  background: 'var(--bg-secondary)',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <span style={{ fontSize: '42px', fontWeight: 'bold', fontFamily: 'var(--font-cyber)', color: getScoreColor(risk_score ?? 0) }}>
                    {risk_score}
                  </span>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '-4px' }}>
                    MAX 99
                  </span>
                </div>
              </div>

              <h2 style={{ 
                color: getScoreColor(risk_score ?? 0), 
                textTransform: 'uppercase', 
                fontSize: '28px',
                fontWeight: '800',
                letterSpacing: '1px',
                marginBottom: '4px'
              }}>
                {risk_classification}
              </h2>
            </div>

            {/* Target Metadata & Actions */}
            <div className="cyber-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '16px' }} className="mono">[ AUDITED MODEL SPECS ]</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '8px', fontSize: '14px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>NAME:</span>
                  <span style={{ fontWeight: '500', wordBreak: 'break-all' }}>{model.name}</span>
                  
                  <span style={{ color: 'var(--text-secondary)' }}>FORMAT:</span>
                  <span className="mono">{model.format}</span>
                  
                  <span style={{ color: 'var(--text-secondary)' }}>SIZE:</span>
                  <span className="mono">{formatBytes(model.file_size)}</span>
                  
                  <span style={{ color: 'var(--text-secondary)' }}>SHA256:</span>
                  <span className="mono" style={{ fontSize: '12px', wordBreak: 'break-all' }}>{model.sha256_hash}</span>
                  
                  <span style={{ color: 'var(--text-secondary)' }}>COMPLETED:</span>
                  <span>{completed_at ? new Date(completed_at).toLocaleString() : ''}</span>
                </div>
              </div>

              <button 
                className="btn-cyber" 
                style={{ width: '100%', marginTop: '24px', borderColor: 'var(--accent-cyan)', color: 'var(--accent-cyan)' }}
                onClick={handleDownloadReport}
              >
                DOWNLOAD FULL REPORT (.MD)
              </button>
            </div>
          </div>

          {/* Guidelines / Recommendation Section */}
          <div className="cyber-card" style={{ 
            marginBottom: '24px', 
            background: 'rgba(13, 18, 46, 0.4)',
            borderLeft: `4px solid ${getScoreColor(risk_score ?? 0)}` 
          }}>
            <h4 style={{ color: getScoreColor(risk_score ?? 0), marginBottom: '8px' }}>
              {risk_classification === 'HIGH RISK' ? '⚠️ CRITICAL WARNING: TAMPERING DETECTED' : 
               risk_classification === 'SUSPICIOUS' ? '⚡ WARNING: ANOMALOUS FEATURES PRESENT' : 
               '✅ SECURITY SYSTEM CLEAR'}
            </h4>
            <p style={{ fontSize: '14px', lineHeight: '1.6', color: 'var(--text-secondary)' }}>
              {risk_classification === 'HIGH RISK' ? 
                'We detected critical vulnerabilities, such as dangerous module references in model opcodes, or known stego patterns. It is highly recommended to block this model file from runtime deployment to protect host servers.' :
               risk_classification === 'SUSPICIOUS' ? 
                'The scanner found statistical anomalies, such as extreme values, NaNs, or highly uniform weight least significant bits. Recommend verifying model origin and training logs.' :
                'All static scans completed successfully. No stego markers, remote code execution imports, or weight outliers were found. The model conforms to expected distributions.'}
            </p>
          </div>

          {/* Findings Log */}
          <h3 style={{ color: 'var(--accent-cyan)', marginBottom: '16px' }} className="glow-text-cyan">[ SECURITY FINDINGS LOG ({findings.length}) ]</h3>
          
          {findings.length === 0 ? (
            <div className="cyber-card" style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '30px' }}>
              No issues detected. Model file metadata is clean.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {findings.map((finding) => (
                <div 
                  key={finding.id} 
                  className="cyber-card" 
                  style={{ 
                    borderLeft: `4px solid ${getSeverityColor(finding.severity)}`,
                    background: 'rgba(13, 18, 46, 0.5)'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
                    <h4 style={{ color: getSeverityColor(finding.severity), fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span>[{finding.severity}]</span>
                      <span>{finding.title}</span>
                    </h4>
                    <span className="mono" style={{ 
                      fontSize: '11px', 
                      background: 'var(--bg-tertiary)', 
                      padding: '2px 6px', 
                      borderRadius: '4px',
                      color: 'var(--accent-cyan)'
                    }}>
                      MODULE: {finding.module}
                    </span>
                  </div>

                  <p style={{ fontSize: '14px', color: 'var(--text-primary)', marginBottom: '12px', lineHeight: '1.5' }}>
                    {finding.description}
                  </p>

                  {finding.layer_name && (
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                      <strong>Target Component/Layer:</strong> <code style={{ color: 'var(--accent-cyan)' }}>{finding.layer_name}</code>
                    </div>
                  )}

                  {finding.evidence && (
                    <div>
                      <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                        TECHNICAL EVIDENCE:
                      </span>
                      <pre style={{
                        background: 'var(--bg-primary)',
                        padding: '12px',
                        borderRadius: '6px',
                        overflowX: 'auto',
                        fontSize: '12px',
                        color: 'var(--accent-cyan)',
                        border: '1px solid var(--border-muted)',
                        fontFamily: 'var(--font-cyber)'
                      }}>
                        {JSON.stringify(finding.evidence, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
