import React, { useState, useEffect } from 'react';
import { api } from './services/api';
import type { ScanHistoryItem, ScanDetail, Model } from './types';
import { FileUpload } from './components/FileUpload';
import { ScanHistory } from './components/ScanHistory';
import { ScanResult } from './components/ScanResult';

export const App: React.FC = () => {
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [scanDetail, setScanDetail] = useState<ScanDetail | null>(null);
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [dbType, setDbType] = useState<string>('Detecting...');
  const [backendStatus, setBackendStatus] = useState<'ONLINE' | 'OFFLINE'>('OFFLINE');

  // Load history and system health on startup
  useEffect(() => {
    checkSystem();
    fetchHistory();
  }, []);

  // Polling logic when scan is active and in progress
  useEffect(() => {
    if (!activeScanId) {
      setScanDetail(null);
      return;
    }

    let intervalId: any;

    const queryScanDetails = async () => {
      try {
        const detail = await api.getScanDetail(activeScanId);
        setScanDetail(detail);
        
        // If scan completes or fails, stop polling and refresh history
        if (detail.status === 'COMPLETED' || detail.status === 'FAILED') {
          fetchHistory();
        } else {
          // Poll every 1.5 seconds if pending/running
          intervalId = setTimeout(queryScanDetails, 1500);
        }
      } catch (err) {
        console.error("Error polling scan details:", err);
      }
    };

    queryScanDetails();

    return () => {
      if (intervalId) clearTimeout(intervalId);
    };
  }, [activeScanId]);

  const checkSystem = async () => {
    try {
      const res = await api.getHealth();
      setDbType(res.database_type);
      setBackendStatus('ONLINE');
    } catch {
      setDbType('NONE');
      setBackendStatus('OFFLINE');
    }
  };

  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      const data = await api.getScanHistory();
      setScans(data);
    } catch (err) {
      console.error("Failed to load history:", err);
    } finally {
      setLoadingHistory(false);
    }
  };

  const handleUploadSuccess = (model: Model) => {
    console.log("Model uploaded successfully:", model);
  };

  const handleScanTriggered = (scanId: number) => {
    setActiveScanId(scanId);
  };

  return (
    <div style={{ padding: '32px 16px', maxWidth: '1280px', margin: '0 auto' }}>
      
      {/* HUD Header Bar */}
      <header style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        borderBottom: '1px solid var(--border-cyber)', 
        paddingBottom: '20px', 
        marginBottom: '32px',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div>
          <h1 className="glow-text-cyan" style={{ 
            fontFamily: 'var(--font-sans)', 
            fontSize: '32px', 
            fontWeight: '800', 
            color: 'var(--accent-cyan)',
            letterSpacing: '2px'
          }}>
            AEGIS // MODEL SECURITY SCANNER
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginTop: '4px' }} className="mono">
            DEFENSIVE STATIC AUDITING & INJECTION RADAR
          </p>
        </div>

        {/* Status Indicators */}
        <div style={{ display: 'flex', gap: '16px', fontSize: '13px' }} className="mono">
          <div style={{ 
            background: 'var(--bg-secondary)', 
            padding: '8px 16px', 
            borderRadius: '4px',
            border: '1px solid var(--border-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <span style={{ color: 'var(--text-secondary)' }}>DATABASE:</span> 
            <span style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>{dbType}</span>
          </div>

          <div style={{ 
            background: 'var(--bg-secondary)', 
            padding: '8px 16px', 
            borderRadius: '4px',
            border: '1px solid var(--border-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <span style={{ color: 'var(--text-secondary)' }}>RADAR:</span> 
            <span style={{ 
              color: backendStatus === 'ONLINE' ? 'var(--accent-green)' : 'var(--accent-red)', 
              fontWeight: 'bold',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <span className={backendStatus === 'ONLINE' ? 'pulse' : ''} style={{ 
                display: 'inline-block',
                width: '8px', 
                height: '8px', 
                borderRadius: '50%', 
                background: backendStatus === 'ONLINE' ? 'var(--accent-green)' : 'var(--accent-red)'
              }}></span>
              {backendStatus}
            </span>
          </div>
        </div>
      </header>

      {/* Main Body Layout */}
      {activeScanId && scanDetail ? (
        <ScanResult scanDetail={scanDetail} onBack={() => setActiveScanId(null)} />
      ) : (
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', 
          gap: '32px' 
        }}>
          <div>
            <FileUpload 
              onUploadSuccess={handleUploadSuccess} 
              onScanTriggered={handleScanTriggered} 
            />
            
            {/* Quick Demo Test Models Reference Panel */}
            <div className="cyber-card" style={{ background: 'rgba(13, 18, 46, 0.3)' }}>
              <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '12px' }} className="mono">[ STATIC TEST FIXTURES ]</h4>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '12px', lineHeight: '1.5' }}>
                Four safe demonstration target models are pre-generated inside the <code style={{ color: 'var(--accent-cyan)' }}>test_models/</code> directory:
              </p>
              <ul style={{ fontSize: '13px', paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '8px', color: 'var(--text-secondary)' }}>
                <li>
                  <strong style={{ color: 'var(--text-primary)' }} className="mono">clean_model.onnx</strong>: Standard network weights. (Result: <span style={{ color: 'var(--accent-green)' }}>CLEAN</span>)
                </li>
                <li>
                  <strong style={{ color: 'var(--text-primary)' }} className="mono">stego_model.onnx</strong>: Embeds safe signature marker <code style={{ color: 'var(--accent-cyan)' }}>"STEGO_DEMO_MARKER_2026"</code>. (Result: <span style={{ color: 'var(--accent-red)' }}>HIGH RISK</span>)
                </li>
                <li>
                  <strong style={{ color: 'var(--text-primary)' }} className="mono">anomalous_model.onnx</strong>: Contains Inf, NaN, and outlier weights. (Result: <span style={{ color: 'var(--accent-orange)' }}>SUSPICIOUS / HIGH RISK</span>)
                </li>
                <li>
                  <strong style={{ color: 'var(--text-primary)' }} className="mono">unsafe_pickle.pth</strong>: Harmless pickle import structure reference. (Result: <span style={{ color: 'var(--accent-red)' }}>HIGH RISK</span>)
                </li>
              </ul>
            </div>
          </div>

          <div>
            <ScanHistory 
              scans={scans} 
              onSelectScan={handleScanTriggered} 
              loading={loadingHistory} 
              onRefresh={fetchHistory}
            />
          </div>
        </div>
      )}

      {/* Decorative footer */}
      <footer style={{ 
        textAlign: 'center', 
        marginTop: '60px', 
        borderTop: '1px solid var(--border-muted)', 
        paddingTop: '20px',
        fontSize: '12px',
        color: 'var(--text-muted)'
      }} className="mono">
        AEGIS SECURE // FIRMWARE STATIC MODEL SCANNER VERSION 1.0.0 (BETA) // SECURED PORT 8000
      </footer>
    </div>
  );
};
export default App;
