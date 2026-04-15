"use client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ChevronLeft, ChevronRight, ScrollText, Search, Shield } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

interface AuditLog { event_id: string; event_type: string; action: string; status: string; severity: string; user_id: string; user_email: string; ip_address: string; resource: string; resource_id: string; details: string; timestamp: string; }
interface AuditStats { total: number; by_event_type: Record<string, number>; by_severity: Record<string, number>; by_status: Record<string, number>; failed_logins: number; recent_count_24h: number; }
const EVENT_LABELS: Record<string,string> = { authentication:"Auth", authorization:"Authz", configuration_change:"Config", data_access:"Data", security_event:"Security" };
const SEV_VARIANTS: Record<string,"default"|"secondary"|"outline"|"destructive"> = { low:"outline", medium:"secondary", high:"default", critical:"destructive" };
const STATUS_VARIANTS: Record<string,"default"|"secondary"|"outline"|"destructive"> = { success:"outline", failed:"secondary", blocked:"destructive" };

export default function AuditLogsView() {
	const [logs, setLogs] = useState<AuditLog[]>([]); const [total, setTotal] = useState(0); const [stats, setStats] = useState<AuditStats|null>(null);
	const [isLoading, setIsLoading] = useState(true); const [search, setSearch] = useState(""); const [eventType, setEventType] = useState("all"); const [severity, setSeverity] = useState("all"); const [status, setStatus] = useState("all"); const [offset, setOffset] = useState(0);
	const PAGE_SIZE = 25;

	const fetchData = useCallback(async () => {
		setIsLoading(true);
		try {
			const params = new URLSearchParams({ offset: String(offset), limit: String(PAGE_SIZE) });
			if (search) params.set("search", search); if (eventType !== "all") params.set("event_type", eventType); if (severity !== "all") params.set("severity", severity); if (status !== "all") params.set("status", status);
			const [logsRes, statsRes] = await Promise.all([fetch(`/api/audit-logs?${params}`, { credentials: "include" }), fetch("/api/enterprise/audit-logs/stats", { credentials: "include" })]);
			if (logsRes.ok) { const data = await logsRes.json(); setLogs(data.audit_logs || []); setTotal(data.total_count || 0); }
			if (statsRes.ok) setStats(await statsRes.json());
		} catch { toast.error("Failed to load audit logs"); } finally { setIsLoading(false); }
	}, [offset, search, eventType, severity, status]);
	useEffect(() => { fetchData(); }, [fetchData]);

	const hasFilters = search || eventType !== "all" || severity !== "all" || status !== "all";
	if (total === 0 && !hasFilters && !isLoading) {
		return (<div className="space-y-4"><div><h2 className="text-lg font-semibold">Audit Logs</h2><p className="text-muted-foreground text-sm">Comprehensive security and compliance audit logging.</p></div>
			<div className="flex flex-col items-center justify-center rounded-sm border py-16"><ScrollText className="text-muted-foreground mb-4 h-12 w-12" strokeWidth={1} /><h3 className="mb-1 text-lg font-medium">No audit logs yet</h3><p className="text-muted-foreground text-sm">Events will appear here as users perform operations.</p></div></div>);
	}

	return (<TooltipProvider><div className="space-y-4">
		<div className="flex items-center justify-between"><div><h2 className="text-lg font-semibold">Audit Logs</h2><p className="text-muted-foreground text-sm">{stats && <>{stats.total} total events, {stats.recent_count_24h} in last 24h{stats.failed_logins > 0 && <span className="text-red-500 ml-2">{stats.failed_logins} failed logins</span>}</>}</p></div></div>

		{stats && stats.total > 0 && (<div className="flex flex-wrap gap-3 text-sm">
			{Object.entries(stats.by_event_type).map(([type, count]) => (<button key={type} type="button" className={`rounded-sm border px-2.5 py-1 text-xs transition-colors ${eventType === type ? "bg-accent" : "hover:bg-accent/50"}`} onClick={() => { setEventType(eventType === type ? "all" : type); setOffset(0); }}>{EVENT_LABELS[type] || type} <span className="text-muted-foreground ml-1">{count}</span></button>))}
			{Object.entries(stats.by_severity).filter(([s]) => s !== "low").map(([sev, count]) => (<button key={sev} type="button" className={`rounded-sm border px-2.5 py-1 text-xs transition-colors ${severity === sev ? "bg-accent" : "hover:bg-accent/50"}`} onClick={() => { setSeverity(severity === sev ? "all" : sev); setOffset(0); }}><Shield className="inline h-3 w-3 mr-0.5" />{sev} <span className="text-muted-foreground ml-1">{count}</span></button>))}
		</div>)}

		<div className="flex flex-wrap items-center gap-3">
			<div className="relative max-w-sm flex-1"><Search className="text-muted-foreground absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2" /><Input placeholder="Search..." value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }} className="pl-9" /></div>
			<Select value={eventType} onValueChange={(v) => { setEventType(v); setOffset(0); }}><SelectTrigger className="w-44"><SelectValue placeholder="Event Type" /></SelectTrigger><SelectContent><SelectItem value="all">All Events</SelectItem><SelectItem value="authentication">Authentication</SelectItem><SelectItem value="authorization">Authorization</SelectItem><SelectItem value="configuration_change">Config Change</SelectItem><SelectItem value="data_access">Data Access</SelectItem><SelectItem value="security_event">Security</SelectItem></SelectContent></Select>
			<Select value={severity} onValueChange={(v) => { setSeverity(v); setOffset(0); }}><SelectTrigger className="w-32"><SelectValue placeholder="Severity" /></SelectTrigger><SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="critical">Critical</SelectItem></SelectContent></Select>
			<Select value={status} onValueChange={(v) => { setStatus(v); setOffset(0); }}><SelectTrigger className="w-32"><SelectValue placeholder="Status" /></SelectTrigger><SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="success">Success</SelectItem><SelectItem value="failed">Failed</SelectItem><SelectItem value="blocked">Blocked</SelectItem></SelectContent></Select>
		</div>

		<div className="rounded-sm border overflow-hidden"><Table><TableHeader><TableRow><TableHead>Timestamp</TableHead><TableHead>Event</TableHead><TableHead>Action</TableHead><TableHead>Status</TableHead><TableHead>Severity</TableHead><TableHead>User</TableHead><TableHead>Resource</TableHead><TableHead>IP</TableHead></TableRow></TableHeader>
			<TableBody>{logs.length === 0 ? (<TableRow><TableCell colSpan={8} className="h-24 text-center"><span className="text-muted-foreground text-sm">No matching audit logs.</span></TableCell></TableRow>) : (
				logs.map((log) => (<TableRow key={log.event_id}><TableCell className="text-muted-foreground text-sm whitespace-nowrap">{new Date(log.timestamp).toLocaleString()}</TableCell>
					<TableCell><Badge variant="outline" className="text-xs">{EVENT_LABELS[log.event_type] || log.event_type}</Badge></TableCell>
					<TableCell className="text-sm font-medium">{log.action}</TableCell>
					<TableCell><Badge variant={STATUS_VARIANTS[log.status] || "outline"}>{log.status}</Badge></TableCell>
					<TableCell><Badge variant={SEV_VARIANTS[log.severity] || "outline"}>{log.severity}</Badge></TableCell>
					<TableCell className="text-sm">{log.user_email}</TableCell>
					<TableCell className="text-sm">{log.resource}{log.resource_id && <Tooltip><TooltipTrigger><span className="text-muted-foreground text-xs ml-1">/{log.resource_id.substring(0, 8)}</span></TooltipTrigger><TooltipContent>{log.resource_id}</TooltipContent></Tooltip>}</TableCell>
					<TableCell className="text-muted-foreground text-sm">{log.ip_address}</TableCell></TableRow>))
			)}</TableBody></Table></div>

		{total > 0 && <div className="flex items-center justify-between px-2"><p className="text-muted-foreground text-sm">Showing {offset + 1}-{Math.min(offset + PAGE_SIZE, total)} of {total}</p><div className="flex gap-2"><Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}><ChevronLeft className="mr-1 h-4 w-4" /> Previous</Button><Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next <ChevronRight className="ml-1 h-4 w-4" /></Button></div></div>}
	</div></TooltipProvider>);
}
