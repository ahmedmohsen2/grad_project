import { Suspense, lazy, useMemo, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import Sidebar from "./components/layout/Sidebar";
import HeaderBar from "./components/layout/HeaderBar";
import AuthGuard from "./components/AuthGuard";
import { NAV_ITEMS } from "./constants/navigation";
import { useSocData } from "./hooks/useSocData";
import SkeletonBlock from "./components/common/SkeletonBlock";
import SuspiciousQueueScreen from "./screens/SuspiciousQueueScreen";
import IncidentsScreen from "./screens/IncidentsScreen";
import HostsScreen from "./screens/HostsScreen";
import ActionsScreen from "./screens/ActionsScreen";
import SystemStatusScreen from "./screens/SystemStatusScreen";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const LiveMonitoringPage = lazy(() => import("./pages/LiveMonitoringPage"));
const AlertsPage = lazy(() => import("./pages/AlertsPage"));
const SecurityToolsPage = lazy(() => import("./pages/SecurityToolsPage"));
const PentestConsolePage = lazy(() => import("./pages/PentestConsolePage"));
const ActivityTimelinePage = lazy(() => import("./pages/ActivityTimelinePage"));
const IncidentView = lazy(() => import("./pages/IncidentView"));
const LoginPage = lazy(() => import("./pages/LoginPage"));
const SignupPage = lazy(() => import("./pages/SignupPage"));

/* ────────────────────────────────────────────────────────────────────────── */
/* Authenticated App Shell — sidebar + header + protected routes             */
/* ────────────────────────────────────────────────────────────────────────── */

function AuthenticatedApp() {
  const [selectedIp, setSelectedIp] = useState("");
  const navigate = useNavigate();
  const location = useLocation();
  const soc = useSocData();

  const currentNav = useMemo(
    () =>
      location.pathname.startsWith("/incident")
        ? {
            id: "incident-view",
            path: location.pathname,
            label: "Incident View",
            description: "Unified incident story across timeline, execution, and report.",
          }
        : NAV_ITEMS.find((item) => location.pathname.startsWith(item.path)) ?? NAV_ITEMS[0],
    [location.pathname],
  );

  const sharedScreenProps = {
    soc,
    selectedIp,
    onSelectIp: setSelectedIp,
    onNavigate: (screenId) => {
      const target = NAV_ITEMS.find((item) => item.id === screenId);
      if (target) {
        navigate(target.path);
      }
    },
    onOpenIncident: (identifier) => {
      if (identifier) {
        navigate(`/incident/${encodeURIComponent(String(identifier))}`);
      }
    },
  };

  return (
    <div className="min-h-screen bg-surface bg-grid bg-[size:32px_32px] text-slate-100">
      {soc.latestActionToast ? (
        <div className="fixed right-6 top-6 z-40 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100 shadow-xl">
          {soc.latestActionToast.message}
        </div>
      ) : null}
      <Sidebar
        items={NAV_ITEMS}
        activeScreen={currentNav.id}
        counts={soc.sidebarCounts}
      />

      <main className="min-h-screen pl-0 lg:pl-[296px]">
        <div className="p-4 md:p-6 xl:p-8">
          <div className="mx-auto max-w-[1680px]">
            <HeaderBar
              title={currentNav.label}
              subtitle={currentNav.description}
              loading={soc.loading}
              lastUpdatedLabel={soc.lastUpdatedLabel}
              newAlertsCount={soc.newAlertsCount}
            />
            <Suspense
              fallback={
                <div className="space-y-4">
                  <SkeletonBlock className="h-40 w-full" />
                  <SkeletonBlock className="h-72 w-full" />
                </div>
              }
            >
              <Routes>
                <Route path="/dashboard" element={<DashboardPage {...sharedScreenProps} />} />
                <Route path="/live-monitoring" element={<LiveMonitoringPage {...sharedScreenProps} />} />
                <Route path="/alerts" element={<AlertsPage {...sharedScreenProps} />} />
                <Route path="/security-tools" element={<SecurityToolsPage />} />
                <Route path="/suspicious-queue" element={<SuspiciousQueueScreen {...sharedScreenProps} />} />
                <Route path="/incidents" element={<IncidentsScreen {...sharedScreenProps} />} />
                <Route path="/hosts" element={<HostsScreen {...sharedScreenProps} />} />
                <Route path="/actions" element={<ActionsScreen {...sharedScreenProps} />} />
                <Route path="/system-status" element={<SystemStatusScreen {...sharedScreenProps} />} />
                <Route path="/pentest" element={<PentestConsolePage {...sharedScreenProps} />} />
                <Route path="/activity-timeline" element={<ActivityTimelinePage {...sharedScreenProps} />} />
                <Route path="/incident" element={<IncidentView {...sharedScreenProps} />} />
                <Route path="/incident/:id" element={<IncidentView {...sharedScreenProps} />} />
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </Suspense>
          </div>
        </div>
      </main>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Root App — handles login/signup vs authenticated shell                    */
/* ────────────────────────────────────────────────────────────────────────── */

function App() {
  return (
    <Suspense
      fallback={
        <div className="flex h-screen items-center justify-center bg-surface">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-sky-500 border-t-transparent" />
        </div>
      }
    >
      <Routes>
        {/* Public routes — no auth required */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />

        {/* All other routes require authentication */}
        <Route
          path="/*"
          element={
            <AuthGuard>
              <AuthenticatedApp />
            </AuthGuard>
          }
        />
      </Routes>
    </Suspense>
  );
}

export default App;
