import { useState, useEffect } from 'react';
import LoginPage from './components/layout/LoginPage';
import App from './components/layout/App';

export default function Root() {
  const [authed, setAuthed] = useState(() => !!localStorage.getItem('zk_token'));

  useEffect(() => {
    const onLogout = () => setAuthed(false);
    window.addEventListener('zk:logout', onLogout);
    return () => window.removeEventListener('zk:logout', onLogout);
  }, []);

  if (!authed) return <LoginPage onLogin={() => setAuthed(true)} />;
  return <App />;
}
