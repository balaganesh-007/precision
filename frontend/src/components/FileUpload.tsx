import React, { useState, useRef } from 'react';
import { api } from '../services/api';
import type { Model } from '../types';

interface FileUploadProps {
  onUploadSuccess: (model: Model) => void;
  onScanTriggered: (scanId: number) => void;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onUploadSuccess, onScanTriggered }) => {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadedModel, setUploadedModel] = useState<Model | null>(null);
  const [scanning, setScanning] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (selectedFile: File) => {
    setError(null);
    setUploadedModel(null);
    const ext = selectedFile.name.split('.').pop()?.toLowerCase();
    const allowed = ['onnx', 'safetensors', 'pt', 'pth', 'bin'];
    
    if (!ext || !allowed.includes(ext)) {
      setError(`Unsupported extension. Supported formats: .onnx, .safetensors, .pt, .pth, .bin`);
      setFile(null);
      return;
    }
    setFile(selectedFile);
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError(null);
    try {
      const res = await api.uploadModel(file);
      setUploadedModel(res.model);
      onUploadSuccess(res.model);
    } catch (err: any) {
      setError(err.message || 'File upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleStartScan = async () => {
    if (!uploadedModel) return;
    setScanning(true);
    setError(null);
    try {
      const scan = await api.startScan(uploadedModel.id);
      onScanTriggered(scan.id);
    } catch (err: any) {
      setError(err.message || 'Failed to start security scan');
    } finally {
      setScanning(false);
    }
  };

  const triggerInputClick = () => {
    inputRef.current?.click();
  };

  return (
    <div className="cyber-card" style={{ marginBottom: '24px' }}>
      <h3 style={{ fontFamily: 'var(--font-sans)', marginBottom: '16px', color: 'var(--accent-cyan)' }} className="glow-text-cyan">
        [ UPLOAD SECURITY TARGET ]
      </h3>
      
      <div 
        className={`drag-area ${dragActive ? 'drag-active' : ''}`}
        onDragEnter={handleDrag}
        onDragOver={handleDrag}
        onDragLeave={handleDrag}
        onDrop={handleDrop}
        style={{
          border: '2px dashed var(--border-cyber)',
          borderRadius: '8px',
          padding: '40px 20px',
          textAlign: 'center',
          background: dragActive ? 'rgba(0, 240, 255, 0.05)' : 'rgba(13, 18, 46, 0.4)',
          cursor: 'pointer',
          transition: 'var(--transition-smooth)',
          marginBottom: '20px'
        }}
        onClick={triggerInputClick}
      >
        <input 
          ref={inputRef}
          type="file"
          style={{ display: 'none' }}
          onChange={handleChange}
          accept=".onnx,.safetensors,.pt,.pth,.bin"
        />
        
        {file ? (
          <div>
            <div style={{ fontSize: '48px', color: 'var(--accent-cyan)', marginBottom: '12px' }}>📁</div>
            <p className="mono" style={{ fontSize: '18px', marginBottom: '8px', wordBreak: 'break-all' }}>{file.name}</p>
            <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
              Size: {(file.size / 1024 / 1024).toFixed(2)} MB
            </p>
          </div>
        ) : (
          <div>
            <div style={{ fontSize: '48px', color: 'var(--text-muted)', marginBottom: '12px' }}>📥</div>
            <p style={{ fontSize: '16px', marginBottom: '8px' }}>Drag & Drop model file or click to browse</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '12px' }} className="mono">
              SUPPORTED: .ONNX | .SAFETENSORS | .PT | .PTH | .BIN
            </p>
          </div>
        )}
      </div>

      {error && (
        <div style={{ 
          background: 'rgba(255, 23, 68, 0.1)', 
          borderLeft: '4px solid var(--accent-red)',
          padding: '12px',
          borderRadius: '4px',
          marginBottom: '16px',
          color: 'var(--text-primary)',
          fontSize: '14px'
        }}>
          <strong>ERROR:</strong> {error}
        </div>
      )}

      <div style={{ display: 'flex', gap: '16px', justifyContent: 'flex-end' }}>
        {file && !uploadedModel && (
          <button 
            className="btn-cyber" 
            onClick={handleUpload}
            disabled={uploading}
          >
            {uploading ? 'UPLOADING...' : 'INDEX MODEL TARGET'}
          </button>
        )}
        
        {uploadedModel && (
          <button 
            className="btn-cyber" 
            style={{ 
              borderColor: 'var(--accent-green)', 
              color: 'var(--accent-green)',
              boxShadow: scanning ? 'none' : '0 0 10px rgba(0,230,118,0.2)' 
            }}
            onClick={handleStartScan}
            disabled={scanning}
          >
            {scanning ? 'INITIALIZING RADAR...' : 'EXECUTE THREAT SCAN'}
          </button>
        )}
      </div>
    </div>
  );
};
