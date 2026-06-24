import { useState, useEffect, Component } from 'react';
import type { ReactNode, ErrorInfo } from 'react';
import LoginPage from './components/layout/LoginPage';
import App from './components/layout/App';

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('[ZK] render crash:', error, info); }
  render() {
    if (this.state.error) {
      const msg = (this.state.error as Error).message;
      return (
        <div style={{ height:'100vh', display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', background:'#1e1e1e', fontFamily:'Courier New', color:'#e05c6e', padding:32 }}>
          <div style={{ fontSize:13, marginBottom:12 }}>⊘ RENDER FAULT — App component crashed</div>
          <div style={{ fontSize:11, color:'#a8a8a8', maxWidth:600, wordBreak:'break-word', lineHeight:1.7 }}>{msg}</div>
          <button onClick={() => this.setState({ error: null })} style={{ marginTop:20, padding:'6px 16px', background:'transparent', border:'1px solid #cc4444', color:'#e05c6e', cursor:'pointer', fontFamily:'Courier New', fontSize:11 }}>
            retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function tokenValid(t: string | null): boolean {
  if (!t) return false;
  try {
    const payload = JSON.parse(atob(t.split('.')[1]));
    return typeof payload.exp === 'number' && payload.exp * 1000 > Date.now();
  } catch {
    return false;
  }
}

export default function Root() {
  const [authed, setAuthed] = useState(() => tokenValid(localStorage.getItem('zk_token')));

  useEffect(() => {
    const onLogout = () => setAuthed(false);
    window.addEventListener('zk:logout', onLogout);
    return () => window.removeEventListener('zk:logout', onLogout);
  }, []);

  if (!authed) return <LoginPage onLogin={() => setAuthed(true)} />;
  return (
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  );
}
