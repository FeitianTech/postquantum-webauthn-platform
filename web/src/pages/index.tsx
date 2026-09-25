import { AppShell } from '@/components/shell/AppShell';
import { ToastProvider } from '@/components/ui/Toast';

export default function Home() {
  return (
    <ToastProvider>
      <AppShell />
    </ToastProvider>
  );
}
