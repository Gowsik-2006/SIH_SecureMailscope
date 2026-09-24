import React from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  Network,
  AlertTriangle,
  Award,
  Sparkles,
  FileCheck2,
  Sliders,
  History,
  Activity,
  Globe,
  Cpu,
  Bug,
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'scanner'
  | 'sensor'
  | 'upload'
  | 'sessions'
  | 'findings'
  | 'certificates'
  | 'anomalies'
  | 'ai'
  | 'reports'
  | 'audit'
  | 'settings'
  | 'health';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  findingsCount: number;
  anomaliesCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  findingsCount,
  anomaliesCount,
}) => {
  const navSections: {
    category: string;
    items: {
      id: NavTab;
      label: string;
      icon: React.ReactNode;
      badge?: number | string;
      badgeColor?: string;
    }[];
  }[] = [
    {
      category: 'Live Network & Ingestion',
      items: [
        {
          id: 'scanner',
          label: 'Live Network Audit',
          icon: <Globe className="w-3.5 h-3.5" />,
          badge: 'ACTIVE',
          badgeColor: 'bg-emerald-950/40 text-emerald-300 border border-emerald-900/60',
        },
        {
          id: 'sensor',
          label: 'Remote Sensor Gateway',
          icon: <Cpu className="w-3.5 h-3.5" />,
        },
        {
          id: 'upload',
          label: 'PCAP Upload & Traces',
          icon: <UploadCloud className="w-3.5 h-3.5" />,
        },
      ],
    },
    {
      category: 'Forensics & Dissection',
      items: [
        {
          id: 'dashboard',
          label: 'Overview',
          icon: <LayoutDashboard className="w-3.5 h-3.5" />,
        },
        {
          id: 'sessions',
          label: 'Session Forensics',
          icon: <Network className="w-3.5 h-3.5" />,
        },
        {
          id: 'findings',
          label: 'Threats & Rules',
          icon: <AlertTriangle className="w-3.5 h-3.5" />,
          badge: findingsCount > 0 ? findingsCount : undefined,
          badgeColor: 'bg-rose-950/40 text-rose-300 border border-rose-900/60 font-mono font-bold',
        },
        {
          id: 'certificates',
          label: 'Certificates (X.509)',
          icon: <Award className="w-3.5 h-3.5" />,
        },
        {
          id: 'anomalies',
          label: 'Wire Anomalies',
          icon: <Bug className="w-3.5 h-3.5" />,
          badge: anomaliesCount > 0 ? anomaliesCount : undefined,
          badgeColor: 'bg-amber-950/40 text-amber-300 border border-amber-900/60 font-mono',
        },
      ],
    },
    {
      category: 'Intelligence & Compliance',
      items: [
        {
          id: 'ai',
          label: 'AI Risk Reasoning',
          icon: <Sparkles className="w-3.5 h-3.5" />,
        },
        {
          id: 'reports',
          label: 'Reports (13 Sections)',
          icon: <FileCheck2 className="w-3.5 h-3.5" />,
        },
        {
          id: 'audit',
          label: 'Audit Trail (SHA-256)',
          icon: <History className="w-3.5 h-3.5" />,
        },
      ],
    },
    {
      category: 'System & Rules',
      items: [
        {
          id: 'settings',
          label: 'Detection Rules',
          icon: <Sliders className="w-3.5 h-3.5" />,
        },
        {
          id: 'health',
          label: 'System Diagnostics',
          icon: <Activity className="w-3.5 h-3.5" />,
        },
      ],
    },
  ];

  return (
    <aside className="w-60 bg-zinc-950 border-r border-zinc-800/80 flex flex-col justify-between py-4 select-none shrink-0">
      <div className="space-y-5 px-3">
        {navSections.map((section, idx) => (
          <div key={idx} className="space-y-1">
            <div className="px-2.5 mb-1.5 text-[10px] font-mono font-semibold uppercase tracking-wider text-zinc-500">
              {section.category}
            </div>

            <nav className="space-y-0.5">
              {section.items.map((item) => {
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectTab(item.id)}
                    className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition cursor-pointer ${
                      isActive
                        ? 'bg-zinc-900 text-zinc-100 border border-zinc-700/60 shadow-xs'
                        : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40 border border-transparent'
                    }`}
                  >
                    <div className="flex items-center space-x-2.5">
                      <span className={isActive ? 'text-zinc-100' : 'text-zinc-500'}>
                        {item.icon}
                      </span>
                      <span>{item.label}</span>
                    </div>

                    {item.badge !== undefined && (
                      <span
                        className={`text-[9px] px-1.5 py-0.2 rounded font-mono ${
                          item.badgeColor || 'bg-zinc-800 text-zinc-300'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>
        ))}
      </div>

      {/* Footer System Status */}
      <div className="px-4 pt-3 border-t border-zinc-850 text-[11px] text-zinc-500 font-mono">
        <div className="flex items-center justify-between mb-1">
          <span>Engine Status</span>
          <span className="flex items-center space-x-1.5 text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>Online</span>
          </span>
        </div>
        <div className="text-[10px] text-zinc-600">SecureMailScope v2.5.0 Production</div>
      </div>
    </aside>
  );
};
