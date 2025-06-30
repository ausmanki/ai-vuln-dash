import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react'; // Using a Lucide icon

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
  errorInfo?: ErrorInfo;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(_: Error): State {
    // Update state so the next render will show the fallback UI.
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // You can also log the error to an error reporting service
    console.error("Uncaught error:", error, errorInfo);
    this.setState({ error, errorInfo });
  }

  render() {
    if (this.state.hasError) {
      // You can render any custom fallback UI
      return (
        <div style={{
          padding: '20px',
          margin: '20px',
          border: '1px solid #ff4d4f', // Red border
          borderRadius: '8px',
          backgroundColor: '#fff1f0', // Light red background
          color: '#cf1322', // Dark red text
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
          minHeight: '200px',
        }}>
          <AlertTriangle size={48} color="#ff4d4f" style={{ marginBottom: '16px' }} />
          <h1 style={{ fontSize: '1.5rem', color: '#cf1322', margin: '0 0 10px 0' }}>Oops! Something went wrong.</h1>
          <p style={{color: '#d4380d'}}>
            We're sorry for the inconvenience. Please try refreshing the page.
          </p>
          {process.env.NODE_ENV === 'development' && this.state.error && (
            <details style={{ marginTop: '20px', whiteSpace: 'pre-wrap', textAlign: 'left', maxWidth: '600px', overflowX: 'auto', background: '#fff', padding: '10px', borderRadius: '4px', border: '1px solid #f0f0f0' }}>
              <summary style={{cursor: 'pointer', fontWeight: 'bold'}}>Error Details (Development Mode)</summary>
              <p><strong>Message:</strong> {this.state.error.toString()}</p>
              {this.state.errorInfo && <p><strong>Stack Trace:</strong><br/>{this.state.errorInfo.componentStack}</p>}
            </details>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
