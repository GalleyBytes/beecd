import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useEffect } from 'react';
import { ThemeProvider } from '@/contexts/ThemeContext';
import { MainLayout } from '@/layouts';
import { AUTH_REDIRECT_EVENT } from '@/lib/api-client';
import {
  HomePage,
  ClustersPage,
  ClusterDetailPage,
  ReposPage,
  RepoDetailPage,
  ServicesPage,
  ServiceDetailPage,
  ServiceNamePage,
  ClusterGroupsPage,
  ClusterGroupDetailPage,
  ReleaseDetailPage,
  LoginPage,
  RegisterPage,
  SettingsPage
} from '@/pages';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30 * 1000, // 30 seconds
      retry: 1,
    },
  },
});

// Component that listens for auth redirect events and navigates using React Router
function AuthRedirectHandler() {
  const navigate = useNavigate();

  useEffect(() => {
    const handleAuthRedirect = () => {
      navigate('/login', { replace: true });
    };

    window.addEventListener(AUTH_REDIRECT_EVENT, handleAuthRedirect);
    return () => {
      window.removeEventListener(AUTH_REDIRECT_EVENT, handleAuthRedirect);
    };
  }, [navigate]);

  return null;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <BrowserRouter>
          <AuthRedirectHandler />
          <Routes>
            {/* Public routes - outside main layout */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            {/* Main app routes */}
            <Route path="/" element={<MainLayout />}>
              <Route index element={<HomePage />} />
              <Route path="clusters" element={<ClustersPage />} />
              <Route path="clusters/:id" element={<ClusterDetailPage />} />
              <Route path="repos" element={<ReposPage />} />
              <Route path="repos/:id" element={<RepoDetailPage />} />
              <Route path="services" element={<ServicesPage />} />
              <Route path="services/name/:name" element={<ServiceNamePage />} />
              <Route path="services/:id" element={<ServiceDetailPage />} />
              <Route path="cluster-groups" element={<ClusterGroupsPage />} />
              <Route path="cluster-groups/:id" element={<ClusterGroupDetailPage />} />
              <Route path="releases/:namespaceId/:releaseName" element={<ReleaseDetailPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="*" element={<div className="text-center py-12"><h1 className="text-2xl font-bold text-gray-900 dark:text-white">404 - Not Found</h1></div>} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
