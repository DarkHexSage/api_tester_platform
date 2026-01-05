import React, { useState } from 'react';
import './App.css';

function App() {
  const [apiMode, setApiMode] = useState('secure');
  const [endpoint, setEndpoint] = useState('');
  const [method, setMethod] = useState('GET');
  const [requestBody, setRequestBody] = useState('');
  const [headers, setHeaders] = useState('');
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [responseTime, setResponseTime] = useState(0);

  // ✅ FOR CADDY: Build full URL with Caddy routing
  const buildUrl = (endpointPath) => {
    if (apiMode === 'secure') {
      return `/security-api/secure/api${endpointPath}`;
    } else {
      return `/security-api/insecure/api${endpointPath}`;
    }
  };

  const handleSendRequest = async () => {
    if (!endpoint.trim()) {
      setError('❌ Please enter an endpoint (e.g., /info, /users, /auth/login)');
      return;
    }

    setLoading(true);
    setError('');
    setResponse(null);
    const startTime = Date.now();

    try {
      // ✅ Build URL through Caddy proxy
      const url = buildUrl(endpoint);
      console.log('🔗 Requesting:', url);

      const config = {
        method: method,
        headers: {
          'Content-Type': 'application/json',
        },
      };

      // Parse custom headers
      if (headers.trim()) {
        try {
          const customHeaders = JSON.parse(headers);
          config.headers = { ...config.headers, ...customHeaders };
        } catch (e) {
          setError('❌ Invalid JSON in headers');
          setLoading(false);
          return;
        }
      }

      // Parse request body for POST/PUT/PATCH
      if (['POST', 'PUT', 'PATCH'].includes(method) && requestBody.trim()) {
        try {
          config.body = JSON.stringify(JSON.parse(requestBody));
        } catch (e) {
          setError('❌ Invalid JSON in request body');
          setLoading(false);
          return;
        }
      }

      // Make fetch request through Caddy
      const res = await fetch(url, config);
      const endTime = Date.now();
      setResponseTime(endTime - startTime);

      // Try to parse JSON response
      let data;
      const contentType = res.headers.get('content-type');
      
      if (contentType && contentType.includes('application/json')) {
        data = await res.json();
      } else {
        const text = await res.text();
        if (text.includes('<!doctype') || text.includes('<html')) {
          setError('❌ API returned HTML instead of JSON. Check if backend is running!');
          setLoading(false);
          return;
        }
        if (!text || text.trim() === '') {
          setError('❌ Empty response from API. Check endpoint path!');
          setLoading(false);
          return;
        }
        data = { raw: text };
      }

      setResponse({
        status: res.status,
        statusText: res.statusText,
        data: data,
        headers: Object.fromEntries(res.headers),
      });

      if (!res.ok) {
        setError(`⚠️ ${res.status} ${res.statusText}`);
      }
    } catch (err) {
      const endTime = Date.now();
      setResponseTime(endTime - startTime);
      console.error('Request failed:', err);
      setError(`❌ ${err.message || 'Request failed. Check if backend APIs are running.'}`);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status) => {
    if (status >= 200 && status < 300) return '#10b981';
    if (status >= 300 && status < 400) return '#6366f1';
    if (status >= 400 && status < 500) return '#f97316';
    return '#ef4444';
  };

  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <h1>🔐 API Testing Console</h1>
          <p className="subtitle">Test and compare Secure vs Insecure API implementations (via Caddy)</p>
        </header>

        <div className="mode-toggle">
          <button
            className={`mode-btn secure ${apiMode === 'secure' ? 'active' : ''}`}
            onClick={() => setApiMode('secure')}
          >
            <span className="mode-indicator"></span>
            Secure API
          </button>
          <button
            className={`mode-btn insecure ${apiMode === 'insecure' ? 'active' : ''}`}
            onClick={() => setApiMode('insecure')}
          >
            <span className="mode-indicator"></span>
            Insecure API
          </button>
        </div>

        <div className="main-content">
          <div className="request-panel">
            <div className="panel-header">
              <h2>Request</h2>
              <span className={`badge ${apiMode}`}>
                {apiMode === 'secure' ? '🔒 Protected' : '⚠️ Unprotected'}
              </span>
            </div>

            <div className="form-group">
              <label>API Base Path (via Caddy)</label>
              <div style={{
                padding: '10px 12px',
                background: 'rgba(255,255,255,0.05)',
                border: '1px solid rgba(255,255,255,0.12)',
                borderRadius: '6px',
                fontFamily: 'Space Mono, monospace',
                fontSize: '12px',
                color: 'rgba(255,255,255,0.8)',
                marginBottom: '12px',
                wordBreak: 'break-all'
              }}>
                /security-api/{apiMode}/api
              </div>
            </div>

            <div className="form-group">
              <label>Endpoint Path</label>
              <input
                type="text"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="/info"
                className="endpoint-field"
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  border: '1px solid rgba(255,255,255,0.12)',
                  borderRadius: '6px',
                  background: 'rgba(255,255,255,0.03)',
                  color: '#ffffff',
                  fontFamily: 'Space Mono, monospace',
                  fontSize: '12px',
                  marginBottom: '6px'
                }}
              />
              <small style={{ color: 'rgba(255,255,255,0.5)', display: 'block', marginTop: '4px' }}>
                Examples:
                <br />
                • /info (GET)
                <br />
                • /users (GET)
                <br />
                • /auth/register (POST)
                <br />
                • /auth/login (POST)
                <br />
                • /users/1 (GET)
                <br />
                • /admin/users (GET)
              </small>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Method</label>
                <select 
                  value={method} 
                  onChange={(e) => setMethod(e.target.value)} 
                  className="select-field"
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid rgba(255,255,255,0.12)',
                    borderRadius: '6px',
                    background: 'rgba(255,255,255,0.03)',
                    color: '#ffffff',
                    fontFamily: 'Space Mono, monospace',
                    fontSize: '12px'
                  }}
                >
                  <option>GET</option>
                  <option>POST</option>
                  <option>PUT</option>
                  <option>PATCH</option>
                  <option>DELETE</option>
                </select>
              </div>
            </div>

            {['POST', 'PUT', 'PATCH'].includes(method) && (
              <div className="form-group">
                <label>Body (JSON)</label>
                <textarea
                  value={requestBody}
                  onChange={(e) => setRequestBody(e.target.value)}
                  placeholder='{"username": "john", "email": "john@example.com", "password": "password123"}'
                  className="textarea-field"
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid rgba(255,255,255,0.12)',
                    borderRadius: '6px',
                    background: 'rgba(255,255,255,0.03)',
                    color: '#ffffff',
                    fontFamily: 'Space Mono, monospace',
                    fontSize: '12px',
                    minHeight: '100px',
                    resize: 'vertical'
                  }}
                  rows="4"
                />
              </div>
            )}

            <div className="form-group">
              <label>Headers (JSON)</label>
              <textarea
                value={headers}
                onChange={(e) => setHeaders(e.target.value)}
                placeholder='{"Authorization": "Bearer token"}'
                className="textarea-field"
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  border: '1px solid rgba(255,255,255,0.12)',
                  borderRadius: '6px',
                  background: 'rgba(255,255,255,0.03)',
                  color: '#ffffff',
                  fontFamily: 'Space Mono, monospace',
                  fontSize: '12px',
                  minHeight: '60px',
                  resize: 'vertical'
                }}
                rows="3"
              />
            </div>

            <button
              onClick={handleSendRequest}
              disabled={loading}
              className={`send-btn ${apiMode}`}
              style={{
                width: '100%',
                padding: '10px 16px',
                border: '1px solid rgba(255,255,255,0.12)',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: '600',
                cursor: loading ? 'not-allowed' : 'pointer',
                transition: 'all 0.25s ease',
                marginTop: '8px',
                textTransform: 'uppercase',
                letterSpacing: '0.3px',
                background: apiMode === 'secure' 
                  ? 'rgba(16, 185, 129, 0.12)' 
                  : 'rgba(239, 68, 68, 0.12)',
                color: apiMode === 'secure' ? '#10b981' : '#ef4444',
                opacity: loading ? 0.5 : 1
              }}
            >
              {loading ? '⏳ Sending...' : '✉️ Send'}
            </button>

            {error && (
              <div style={{
                marginTop: '12px',
                padding: '10px 12px',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.2)',
                borderLeft: '3px solid #ef4444',
                borderRadius: '4px',
                color: 'rgba(239, 68, 68, 0.9)',
                fontSize: '12px',
                fontWeight: '500'
              }}>
                {error}
              </div>
            )}
          </div>

          <div className="response-panel">
            <div className="panel-header">
              <h2>Response</h2>
              {response && (
                <span className="response-meta">
                  <span 
                    className="status-badge" 
                    style={{ color: getStatusColor(response.status) }}
                  >
                    {response.status}
                  </span>
                  <span className="response-time" style={{
                    fontSize: '11px',
                    color: 'rgba(255,255,255,0.5)',
                    fontFamily: 'Space Mono, monospace',
                    fontWeight: '400',
                    marginLeft: '10px'
                  }}>
                    {responseTime}ms
                  </span>
                </span>
              )}
            </div>

            {response ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxHeight: '600px', overflowY: 'auto' }}>
                <div style={{
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '6px',
                  padding: '12px'
                }}>
                  <h3 style={{
                    fontSize: '11px',
                    fontWeight: '600',
                    color: 'rgba(255,255,255,0.7)',
                    marginBottom: '8px',
                    letterSpacing: '0.2px',
                    textTransform: 'uppercase'
                  }}>
                    Status
                  </h3>
                  <div style={{
                    fontSize: '13px',
                    color: getStatusColor(response.status)
                  }}>
                    {response.status} {response.statusText}
                  </div>
                </div>

                <div style={{
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '6px',
                  padding: '12px'
                }}>
                  <h3 style={{
                    fontSize: '11px',
                    fontWeight: '600',
                    color: 'rgba(255,255,255,0.7)',
                    marginBottom: '8px',
                    letterSpacing: '0.2px',
                    textTransform: 'uppercase'
                  }}>
                    Body
                  </h3>
                  <pre style={{
                    background: 'rgba(0,0,0,0.3)',
                    padding: '10px',
                    borderRadius: '4px',
                    color: 'rgba(255,255,255,0.8)',
                    fontFamily: 'Space Mono, monospace',
                    fontSize: '11px',
                    overflow: 'auto',
                    border: '1px solid rgba(255,255,255,0.08)',
                    lineHeight: '1.4',
                    maxHeight: '400px'
                  }}>
                    {JSON.stringify(response.data, null, 2)}
                  </pre>
                </div>

                {Object.keys(response.headers).length > 0 && (
                  <div style={{
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '6px',
                    padding: '12px'
                  }}>
                    <h3 style={{
                      fontSize: '11px',
                      fontWeight: '600',
                      color: 'rgba(255,255,255,0.7)',
                      marginBottom: '8px',
                      letterSpacing: '0.2px',
                      textTransform: 'uppercase'
                    }}>
                      Headers
                    </h3>
                    <pre style={{
                      background: 'rgba(0,0,0,0.3)',
                      padding: '10px',
                      borderRadius: '4px',
                      color: 'rgba(255,255,255,0.8)',
                      fontFamily: 'Space Mono, monospace',
                      fontSize: '11px',
                      overflow: 'auto',
                      border: '1px solid rgba(255,255,255,0.08)',
                      lineHeight: '1.4',
                      maxHeight: '200px'
                    }}>
                      {JSON.stringify(response.headers, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '280px',
                color: 'rgba(255,255,255,0.4)',
                fontSize: '13px',
                letterSpacing: '0.2px'
              }}>
                <p>📤 Send a request to see response here</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
