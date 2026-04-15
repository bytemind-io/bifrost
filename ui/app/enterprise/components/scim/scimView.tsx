"use client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ChevronLeft, ChevronRight, Search, Users } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

interface UserStats { total: number; active: number; inactive: number; by_role: Record<string, number>; active_sessions: number; }
interface User { id: string; name: string; email: string; role: string; team_id?: string; is_active: boolean; created_at: string; }

export default function SCIMView() {
	const [stats, setStats] = useState<UserStats | null>(null);
	const [users, setUsers] = useState<User[]>([]); const [total, setTotal] = useState(0); const [isLoading, setIsLoading] = useState(true);
	const [search, setSearch] = useState(""); const [roleFilter, setRoleFilter] = useState("all"); const [statusFilter, setStatusFilter] = useState("all"); const [offset, setOffset] = useState(0);
	const [availableRoles, setAvailableRoles] = useState<{ name: string }[]>([]);
	const [teamNames, setTeamNames] = useState<Record<string, string>>({});
	const PAGE_SIZE = 25;

	const fetchData = useCallback(async () => {
		setIsLoading(true);
		try {
			const params = new URLSearchParams({ offset: String(offset), limit: String(PAGE_SIZE) });
			if (search) params.set("search", search); if (roleFilter !== "all") params.set("role", roleFilter); if (statusFilter !== "all") params.set("is_active", statusFilter);
			const [statsRes, usersRes] = await Promise.all([fetch("/api/enterprise/users/stats", { credentials: "include" }), fetch(`/api/enterprise/users?${params}`, { credentials: "include" })]);
			if (statsRes.ok) setStats(await statsRes.json());
			if (usersRes.ok) { const data = await usersRes.json(); setUsers(data.data || []); setTotal(data.total || 0); }
		} catch { toast.error("Failed to load data"); } finally { setIsLoading(false); }
	}, [offset, search, roleFilter, statusFilter]);

	useEffect(() => { fetchData(); }, [fetchData]);
	useEffect(() => {
		fetch("/api/roles", { credentials: "include" }).then((res) => (res.ok ? res.json() : [])).then((roles) => setAvailableRoles(roles.map((r: any) => ({ name: r.name })))).catch(() => {});
		fetch("/api/governance/teams", { credentials: "include" }).then((res) => (res.ok ? res.json() : { teams: [] })).then((data) => {
			const map: Record<string, string> = {}; for (const t of data.teams || []) { if (t && typeof t === "object") map[t.id] = t.name; } setTeamNames(map);
		}).catch(() => {});
	}, []);

	return (<div className="space-y-4">
		<div><h2 className="text-lg font-semibold">User Provisioning</h2><p className="text-muted-foreground text-sm">Overview of provisioned users.{stats && <> {stats.total} total, {stats.active} active, {stats.active_sessions} sessions.</>}</p></div>
		<div className="flex flex-wrap items-center gap-3">
			<div className="relative max-w-sm flex-1"><Search className="text-muted-foreground absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2" /><Input placeholder="Search by name or email..." value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }} className="pl-9" /></div>
			<Select value={roleFilter} onValueChange={(v) => { setRoleFilter(v); setOffset(0); }}><SelectTrigger className="w-32"><SelectValue placeholder="Role" /></SelectTrigger><SelectContent><SelectItem value="all">All Roles</SelectItem>{availableRoles.map((r) => (<SelectItem key={r.name} value={r.name}>{r.name}</SelectItem>))}</SelectContent></Select>
			<Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setOffset(0); }}><SelectTrigger className="w-32"><SelectValue placeholder="Status" /></SelectTrigger><SelectContent><SelectItem value="all">All Status</SelectItem><SelectItem value="true">Active</SelectItem><SelectItem value="false">Inactive</SelectItem></SelectContent></Select>
		</div>
		<div className="rounded-sm border overflow-hidden"><Table><TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Email</TableHead><TableHead>Role</TableHead><TableHead>Status</TableHead><TableHead>Team</TableHead><TableHead>Provisioned</TableHead></TableRow></TableHeader>
			<TableBody>{users.length === 0 ? (<TableRow><TableCell colSpan={6} className="h-24 text-center">{isLoading ? <span className="text-muted-foreground text-sm">Loading...</span> : <div className="flex flex-col items-center"><Users className="text-muted-foreground mb-2 h-8 w-8" strokeWidth={1} /><span className="text-muted-foreground text-sm">No users found.</span></div>}</TableCell></TableRow>) : (
				users.map((user) => (<TableRow key={user.id}><TableCell className="font-medium">{user.name}</TableCell><TableCell>{user.email}</TableCell>
					<TableCell><Badge variant="secondary">{user.role}</Badge></TableCell>
					<TableCell><Badge variant={user.is_active ? "outline" : "secondary"}>{user.is_active ? "Active" : "Inactive"}</Badge></TableCell>
					<TableCell className="text-muted-foreground text-sm">{user.team_id ? (teamNames[user.team_id] || "Unknown Team") : "-"}</TableCell>
					<TableCell className="text-muted-foreground text-sm">{new Date(user.created_at).toLocaleDateString()}</TableCell></TableRow>))
			)}</TableBody></Table></div>
		{total > 0 && <div className="flex items-center justify-between px-2"><p className="text-muted-foreground text-sm">Showing {offset + 1}-{Math.min(offset + PAGE_SIZE, total)} of {total}</p><div className="flex gap-2"><Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}><ChevronLeft className="mr-1 h-4 w-4" /> Previous</Button><Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next <ChevronRight className="ml-1 h-4 w-4" /></Button></div></div>}
	</div>);
}
