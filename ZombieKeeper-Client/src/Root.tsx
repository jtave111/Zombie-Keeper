import { useState, useEffect } from 'react';
import LoginPage from './components/layout/LoginPage';
import App from './components/layout/App';

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
  return <App />;
}
