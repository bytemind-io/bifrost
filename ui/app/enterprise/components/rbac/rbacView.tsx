"use client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdownMenu";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alertDialog";
import { MoreHorizontal, Plus, Shield } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

interface Role { id: string; name: string; description: string; is_system: boolean; permission_count: number; }
interface Permission { id: string; role_id: string; resource: string; operation: string; }
const ALL_RESOURCES = ["Logs","ModelProvider","Observability","Plugins","VirtualKeys","UserProvisioning","Users","AuditLogs","GuardrailsConfig","GuardrailRules","Cluster","Settings","MCPGateway","AdaptiveRouter"];
const ALL_OPERATIONS = ["View","Create","Update","Delete"];
const RESOURCE_LABELS: Record<string,string> = { Logs:"Logs",ModelProvider:"Model Providers",Observability:"Observability",Plugins:"Plugins",VirtualKeys:"Virtual Keys",UserProvisioning:"User Provisioning",Users:"Users",AuditLogs:"Audit Logs",GuardrailsConfig:"Guardrails Config",GuardrailRules:"Guardrail Rules",Cluster:"Cluster",Settings:"Settings",MCPGateway:"MCP Gateway",AdaptiveRouter:"Adaptive Router" };

export default function RBACView() {
	const [roles, setRoles] = useState<Role[]>([]); const [isLoading, setIsLoading] = useState(true);
	const [createOpen, setCreateOpen] = useState(false); const [newName, setNewName] = useState(""); const [newDesc, setNewDesc] = useState(""); const [isSaving, setIsSaving] = useState(false);
	const [permRole, setPermRole] = useState<Role | null>(null); const [permOpen, setPermOpen] = useState(false);
	const [permissions, setPermissions] = useState<Record<string, Record<string, boolean>>>({}); const [selectedResource, setSelectedResource] = useState(ALL_RESOURCES[0]);
	const [deleteRole, setDeleteRoleState] = useState<Role | null>(null);

	const fetchRoles = useCallback(async () => {
		setIsLoading(true);
		try { const res = await fetch("/api/roles", { credentials: "include" }); if (res.ok) setRoles(await res.json()); } catch { toast.error("Failed to load roles"); } finally { setIsLoading(false); }
	}, []);
	useEffect(() => { fetchRoles(); }, [fetchRoles]);

	const handleCreateRole = async () => {
		if (!newName.trim()) return; setIsSaving(true);
		try { const res = await fetch("/api/roles", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include", body: JSON.stringify({ name: newName, description: newDesc }) });
			if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error?.message || d.message || "Failed"); }
			setCreateOpen(false); setNewName(""); setNewDesc(""); toast.success("Role created"); fetchRoles();
		} catch (err: any) { toast.error(err.message); } finally { setIsSaving(false); }
	};
	const handleDeleteRole = async () => {
		if (!deleteRole) return;
		try { const res = await fetch(`/api/roles/${deleteRole.id}`, { method: "DELETE", credentials: "include" });
			if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error?.message || "Failed"); }
			toast.success("Role deleted"); setDeleteRoleState(null); fetchRoles();
		} catch (err: any) { toast.error(err.message); }
	};
	const openManagePermissions = async (role: Role) => {
		try { const res = await fetch(`/api/roles/${role.id}/permissions`, { credentials: "include" }); if (!res.ok) throw new Error("Failed");
			const perms: Permission[] = await res.json();
			const map: Record<string, Record<string, boolean>> = {};
			for (const r of ALL_RESOURCES) { map[r] = {}; for (const op of ALL_OPERATIONS) map[r][op] = false; }
			for (const p of perms) { if (map[p.resource]) map[p.resource][p.operation] = true; }
			setPermissions(map); setPermRole(role); setSelectedResource(ALL_RESOURCES[0]); setPermOpen(true);
		} catch (err: any) { toast.error(err.message); }
	};
	const handleSavePermissions = async () => {
		if (!permRole) return; setIsSaving(true);
		try { const permList: { resource: string; operation: string }[] = [];
			for (const [resource, ops] of Object.entries(permissions)) { for (const [op, enabled] of Object.entries(ops)) { if (enabled) permList.push({ resource, operation: op }); } }
			const res = await fetch(`/api/roles/${permRole.id}/permissions`, { method: "PUT", headers: { "Content-Type": "application/json" }, credentials: "include", body: JSON.stringify(permList) });
			if (!res.ok) throw new Error("Failed"); setPermOpen(false); toast.success("Permissions updated"); fetchRoles();
		} catch (err: any) { toast.error(err.message); } finally { setIsSaving(false); }
	};
	const togglePerm = (resource: string, operation: string) => { setPermissions((prev) => ({ ...prev, [resource]: { ...prev[resource], [operation]: !prev[resource]?.[operation] } })); };
	const getResCount = (resource: string) => { const ops = permissions[resource] || {}; return `${Object.values(ops).filter(Boolean).length}/${ALL_OPERATIONS.length}`; };
	const getTotalCount = () => { let t = 0; for (const ops of Object.values(permissions)) { t += Object.values(ops).filter(Boolean).length; } return t; };

	if (isLoading) return null;
	return (<div className="space-y-4">
		<div className="flex items-center justify-between"><div><h2 className="text-lg font-semibold">Roles & Permissions</h2><p className="text-muted-foreground text-sm">Manage user access with fine-grained permissions across Bifrost resources.</p></div>
		<Button onClick={() => { setNewName(""); setNewDesc(""); setCreateOpen(true); }}><Plus className="h-4 w-4" /> Add Role</Button></div>
		<div className="rounded-sm border overflow-hidden"><Table><TableHeader><TableRow><TableHead>Role</TableHead><TableHead>Description</TableHead><TableHead className="text-center">Permissions</TableHead><TableHead className="text-center">Type</TableHead><TableHead className="w-12"></TableHead></TableRow></TableHeader>
			<TableBody>{roles.length === 0 ? (<TableRow><TableCell colSpan={5} className="h-24 text-center"><Shield className="text-muted-foreground mx-auto mb-2 h-8 w-8" strokeWidth={1} /><span className="text-muted-foreground text-sm">No roles.</span></TableCell></TableRow>) : (
				roles.map((role) => (<TableRow key={role.id} className="group"><TableCell className="font-medium">{role.name}</TableCell><TableCell className="text-muted-foreground text-sm">{role.description}</TableCell>
					<TableCell className="text-center"><Badge variant="secondary">{role.permission_count}</Badge></TableCell>
					<TableCell className="text-center"><Badge variant={role.is_system ? "outline" : "secondary"}>{role.is_system ? "System" : "Custom"}</Badge></TableCell>
					<TableCell><DropdownMenu><DropdownMenuTrigger asChild><Button variant="ghost" size="icon" className="h-8 w-8"><MoreHorizontal className="h-4 w-4" /></Button></DropdownMenuTrigger>
						<DropdownMenuContent align="end"><DropdownMenuItem onClick={() => openManagePermissions(role)}>Manage Permissions</DropdownMenuItem>
						{!role.is_system && <DropdownMenuItem onClick={() => setDeleteRoleState(role)}>Delete Role</DropdownMenuItem>}</DropdownMenuContent></DropdownMenu></TableCell>
				</TableRow>)))}</TableBody></Table></div>

		<Dialog open={createOpen} onOpenChange={setCreateOpen}><DialogContent><DialogHeader><DialogTitle>Create Role</DialogTitle><DialogDescription>Create a custom role.</DialogDescription></DialogHeader>
			<div className="space-y-4 py-2"><div className="space-y-2"><Label>Role Name</Label><Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder='e.g. "Auditor"' /></div>
			<div className="space-y-2"><Label>Description</Label><Input value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="Purpose" /></div></div>
			<DialogFooter><Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button><Button onClick={handleCreateRole} disabled={isSaving || !newName.trim()}>{isSaving ? "Creating..." : "Create Role"}</Button></DialogFooter></DialogContent></Dialog>

		<Dialog open={permOpen} onOpenChange={setPermOpen}><DialogContent className="max-w-2xl"><DialogHeader><DialogTitle>Manage Permissions — {permRole?.name}</DialogTitle><DialogDescription>Toggle permissions for each resource.</DialogDescription></DialogHeader>
			<div className="flex gap-0 border rounded-sm min-h-[350px]">
				<div className="w-1/2 border-r overflow-y-auto">{ALL_RESOURCES.map((resource) => (<button key={resource} type="button" className={`flex w-full items-center justify-between px-3 py-2.5 text-left text-sm transition-colors hover:bg-accent ${selectedResource === resource ? "bg-accent" : ""}`} onClick={() => setSelectedResource(resource)}><span>{RESOURCE_LABELS[resource] || resource}</span><span className="text-muted-foreground text-xs">{getResCount(resource)}</span></button>))}</div>
				<div className="w-1/2 p-4 space-y-4"><h4 className="text-sm font-medium">{RESOURCE_LABELS[selectedResource] || selectedResource}</h4>
					{ALL_OPERATIONS.map((op) => (<div key={op} className="flex items-center justify-between"><div><p className="text-sm font-medium">{op}</p><p className="text-muted-foreground text-xs">{op === "View" && "Read-only access"}{op === "Create" && "Create new instances"}{op === "Update" && "Modify existing"}{op === "Delete" && "Remove resources"}</p></div><Switch checked={permissions[selectedResource]?.[op] || false} onCheckedChange={() => togglePerm(selectedResource, op)} /></div>))}</div>
			</div>
			<DialogFooter className="flex items-center justify-between"><span className="text-muted-foreground text-sm">{getTotalCount()} of {ALL_RESOURCES.length * ALL_OPERATIONS.length} permissions</span><div className="flex gap-2"><Button variant="outline" onClick={() => setPermOpen(false)}>Cancel</Button><Button onClick={handleSavePermissions} disabled={isSaving}>{isSaving ? "Saving..." : "Save Permissions"}</Button></div></DialogFooter></DialogContent></Dialog>

		<AlertDialog open={!!deleteRole} onOpenChange={(open) => { if (!open) setDeleteRoleState(null); }}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Delete Role</AlertDialogTitle><AlertDialogDescription>Delete &quot;{deleteRole?.name}&quot;? Users with this role will lose permissions.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Cancel</AlertDialogCancel><AlertDialogAction onClick={handleDeleteRole}>Delete</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
	</div>);
}
