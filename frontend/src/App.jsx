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

  const SECURE_API = 'http://localhost:3000';
  const INSECURE_API = 'http://localhost:3001';

  const currentAPI = apiMode === 'secure' ? SECURE_API : INSECURE_API;

  const handleSendRequest = async () => {
    if (!endpoint.trim()) {
      setError('Please enter an endpoint');
      return;
    }

    setLoading(true);
    setError('');
    setResponse(null);
    const startTime = Date.now();

    try {
      const config = {
        method: method,
        url: `${currentAPI}${endpoint}`,
        headers: {
          'Content-Type': 'application/json',
        },
      };

      if (headers.trim()) {
        try {
          const customHeaders = JSON.parse(headers);
          config.headers = { ...config.headers, ...customHeaders };
        } catch (e) {
          setError('Invalid JSON in headers');
          setLoading(false);
          return;
        }
      }

      if (['POST', 'PUT', 'PATCH'].includes(method) && requestBody.trim()) {
        try {
          config.data = JSON.parse(requestBody);
        } catch (e) {
          setError('Invalid JSON in request body');
          setLoading(false);
          return;
        }
      }

      const res = await fetch(config.url, {
        method: config.method,
        headers: config.headers,
        body: config.data ? JSON.stringify(config.data) : undefined,
      });

      const endTime = Date.now();
      setResponseTime(endTime - startTime);

      const data = await res.json();
      setResponse({
        status: res.status,
        statusText: res.statusText,
        data: data,
        headers: Object.fromEntries(res.headers),
      });

      if (!res.ok) {
        setError(`Error: ${res.status} ${res.statusText}`);
      }
    } catch (err) {
      const endTime = Date.now();
      setResponseTime(endTime - startTime);
      setError(err.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status) => {
    if (status >= 200 && status < 300) return '#10b981';
    if (status >= 300 && status < 400) return '#3b82f6';
    if (status >= 400 && status < 500) return '#f97316';
    return '#ef4444';
  };

  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <h1>API Testing Dashboard</h1>
          <p className="subtitle">Test and compare Secure vs Insecure API implementations</p>
        </header>

        <div className="mode-toggle">
          <button
            className={`mode-btn ${apiMode === 'secure' ? 'active secure' : ''}`}
            onClick={() => setApiMode('secure')}
          >
            <span className="mode-indicator secure"></span>
            Secure API
          </button>
          <button
            className={`mode-btn ${apiMode === 'insecure' ? 'active insecure' : ''}`}
            onClick={() => setApiMode('insecure')}
          >
            <span className="mode-indicator insecure"></span>
            Insecure API
          </button>
        </div>

        <div className="main-content">
          <div className="request-panel">
            <div className="panel-title">
              <h2>Request Configuration</h2>
              <span className={`api-label ${apiMode}`}>
                {apiMode === 'secure' ? '🔒 Secure' : '⚠️ Insecure'}
              </span>
            </div>

            <div className="form-group">
              <label>API Endpoint</label>
              <div className="endpoint-input">
                <span className="base-url">{currentAPI}</span>
                <input
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  placeholder="/api/users"
                  className="endpoint-field"
                />
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Method</label>
                <select value={method} onChange={(e) => setMethod(e.target.value)} className="select-field">
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
                <label>Request Body (JSON)</label>
                <textarea
                  value={requestBody}
                  onChange={(e) => setRequestBody(e.target.value)}
                  placeholder='{"key": "value"}'
                  className="textarea-field"
                  rows="5"
                />
              </div>
            )}

            <div className="form-group">
              <label>Custom Headers (JSON)</label>
              <textarea
                value={headers}
                onChange={(e) => setHeaders(e.target.value)}
                placeholder='{"Authorization": "Bearer token"}'
                className="textarea-field"
                rows="4"
              />
            </div>

            <button
              onClick={handleSendRequest}
              disabled={loading}
              className={`send-btn ${apiMode}`}
            >
              {loading ? 'Sending...' : 'Send Request'}
            </button>

            {error && <div className="error-message">{error}</div>}
          </div>

          <div className="response-panel">
            <div className="panel-title">
              <h2>Response</h2>
              {response && (
                <span className="response-meta">
                  <span className="status-badge" style={{ color: getStatusColor(response.status) }}>
                    {response.status}
                  </span>
                  <span className="response-time">{responseTime}ms</span>
                </span>
              )}
            </div>

            {response ? (
              <div className="response-content">
                <div className="response-section">
                  <h3>Status</h3>
                  <div className="response-item">
                    <span className="label">Code:</span>
                    <span style={{ color: getStatusColor(response.status) }}>
                      {response.status} {response.statusText}
                    </span>
                  </div>
                </div>

                <div className="response-section">
                  <h3>Body</h3>
                  <pre className="response-data">
                    {JSON.stringify(response.data, null, 2)}
                  </pre>
                </div>

                <div className="response-section">
                  <h3>Headers</h3>
                  <pre className="response-data">
                    {JSON.stringify(response.headers, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <p>📤 Send a request to see the response here</p>
              </div>
            )}
          </div>
        </div>

        <footer className="footer">
          <p>💡 Use this dashboard to test and compare API security implementations</p>
          <p>🔒 Secure API enforces best practices | ⚠️ Insecure API demonstrates vulnerabilities</p>
        </footer>
      </div>
    </div>
  );
}

export default App;
