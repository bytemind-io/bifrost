"use client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alertDialog";
import { ChevronLeft, ChevronRight, Copy, Edit, Plus, Search, Trash2, Users } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

interface User { id: string; name: string; email: string; role: string; team_id?: string; is_active: boolean; created_at: string; }
interface UserFormData { email: string; name: string; password: string; role: string; }
interface RoleOption { id: string; name: string; }
const emptyForm: UserFormData = { email: "", name: "", password: "", role: "Viewer" };
const formatUserId = (id: string) => id.length > 12 ? `${id.slice(0, 8)}...${id.slice(-4)}` : id;

export default function UsersView() {
	const [users, setUsers] = useState<User[]>([]); const [total, setTotal] = useState(0);
	const [isLoading, setIsLoading] = useState(true); const [search, setSearch] = useState(""); const [offset, setOffset] = useState(0);
	const [dialogOpen, setDialogOpen] = useState(false); const [editingUser, setEditingUser] = useState<User | null>(null);
	const [formData, setFormData] = useState<UserFormData>(emptyForm); const [isSaving, setIsSaving] = useState(false); const [error, setError] = useState("");
	const [availableRoles, setAvailableRoles] = useState<RoleOption[]>([]);
	const canCreate = useRbac(RbacResource.Users, RbacOperation.Create);
	const canUpdate = useRbac(RbacResource.Users, RbacOperation.Update);
	const canDelete = useRbac(RbacResource.Users, RbacOperation.Delete);
	const { copy: copyUserId } = useCopyToClipboard({ successMessage: "User ID copied" });
	const PAGE_SIZE = 25;

	const fetchUsers = useCallback(async () => {
		setIsLoading(true);
		try {
			const params = new URLSearchParams({ offset: String(offset), limit: String(PAGE_SIZE) });
			if (search) params.set("search", search);
			const res = await fetch(`/api/enterprise/users?${params}`, { credentials: "include" });
			if (res.ok) { const data = await res.json(); setUsers(data.data || []); setTotal(data.total || 0); }
		} catch { toast.error("Failed to load users"); } finally { setIsLoading(false); }
	}, [offset, search]);

	useEffect(() => { fetchUsers(); }, [fetchUsers]);
	useEffect(() => {
		fetch("/api/roles", { credentials: "include" }).then((res) => (res.ok ? res.json() : [])).then((roles) => setAvailableRoles(roles.map((r: any) => ({ id: r.id, name: r.name })))).catch(() => {});
	}, []);

	const handleSave = async () => {
		setIsSaving(true); setError("");
		try {
			const isEdit = !!editingUser;
			const url = isEdit ? `/api/enterprise/users/${editingUser!.id}` : "/api/enterprise/users";
			const body: Record<string, any> = { name: formData.name, role: formData.role };
			if (!isEdit) { body.email = formData.email; body.password = formData.password; }
			if (isEdit && formData.password) { body.password = formData.password; }
			const res = await fetch(url, { method: isEdit ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, credentials: "include", body: JSON.stringify(body) });
			if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error?.message || d.message || "Failed"); }
			setDialogOpen(false); toast.success(isEdit ? "User updated" : "User created"); fetchUsers();
		} catch (err: any) { setError(err.message); } finally { setIsSaving(false); }
	};

	const handleDelete = async (user: User) => {
		try { const res = await fetch(`/api/enterprise/users/${user.id}`, { method: "DELETE", credentials: "include" }); if (res.ok) { toast.success("User deleted"); fetchUsers(); } } catch { toast.error("Failed"); }
	};

	if (total === 0 && !search && !isLoading) {
		return (<div className="space-y-4">
			<div className="flex items-center justify-between"><div><h2 className="text-lg font-semibold">Users</h2><p className="text-muted-foreground text-sm">Manage enterprise users with role-based access control.</p></div>
			{canCreate && <Button onClick={() => { setEditingUser(null); setFormData(emptyForm); setError(""); setDialogOpen(true); }}><Plus className="h-4 w-4" /> Add User</Button>}</div>
			<div className="flex flex-col items-center justify-center rounded-sm border py-16"><Users className="text-muted-foreground mb-4 h-12 w-12" strokeWidth={1} /><h3 className="mb-1 text-lg font-medium">No users yet</h3><p className="text-muted-foreground mb-4 text-sm">Create your first user to get started.</p>
			{canCreate && <Button onClick={() => { setEditingUser(null); setFormData(emptyForm); setError(""); setDialogOpen(true); }}><Plus className="h-4 w-4" /> Add User</Button>}</div>
			{renderDialog()}
		</div>);
	}

	function renderDialog() {
		return (<Dialog open={dialogOpen} onOpenChange={setDialogOpen}><DialogContent><DialogHeader><DialogTitle>{editingUser ? "Edit User" : "Create User"}</DialogTitle><DialogDescription>{editingUser ? "Update user details." : "Add a new user."}</DialogDescription></DialogHeader>
			<div className="space-y-4 py-2">
				{error && <div className="bg-destructive/10 text-destructive rounded-sm p-3 text-sm">{error}</div>}
				{!editingUser && <div className="space-y-2"><Label>Email</Label><Input type="email" value={formData.email} onChange={(e) => setFormData({ ...formData, email: e.target.value })} placeholder="user@example.com" /></div>}
				<div className="space-y-2"><Label>Name</Label><Input value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} placeholder="Full name" /></div>
				{!editingUser && <div className="space-y-2"><Label>Password</Label><Input type="password" value={formData.password} onChange={(e) => setFormData({ ...formData, password: e.target.value })} placeholder="Min 8 characters" /></div>}
				{editingUser && <div className="space-y-2"><Label>Reset Password (optional)</Label><Input type="password" value={formData.password} onChange={(e) => setFormData({ ...formData, password: e.target.value })} placeholder="Leave empty to keep current" /></div>}
				<div className="space-y-2"><Label>Role</Label><Select value={formData.role} onValueChange={(val) => setFormData({ ...formData, role: val })}><SelectTrigger><SelectValue placeholder="Select role" /></SelectTrigger><SelectContent>{availableRoles.map((r) => (<SelectItem key={r.id} value={r.name}>{r.name}</SelectItem>))}</SelectContent></Select></div>
			</div>
			<DialogFooter><Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button><Button onClick={handleSave} disabled={isSaving}>{isSaving ? "Saving..." : editingUser ? "Update" : "Create"}</Button></DialogFooter>
		</DialogContent></Dialog>);
	}

	return (<div className="space-y-4">
		<div className="flex items-center justify-between"><div><h2 className="text-lg font-semibold">Users</h2><p className="text-muted-foreground text-sm">Manage enterprise users with role-based access control.</p></div>
		{canCreate && <Button onClick={() => { setEditingUser(null); setFormData(emptyForm); setError(""); setDialogOpen(true); }}><Plus className="h-4 w-4" /> Add User</Button>}</div>
		<div className="flex items-center gap-3"><div className="relative max-w-sm flex-1"><Search className="text-muted-foreground absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2" /><Input placeholder="Search by name or email..." value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }} className="pl-9" /></div></div>
		<div className="rounded-sm border overflow-hidden"><Table><TableHeader><TableRow><TableHead>Name</TableHead><TableHead>User ID</TableHead><TableHead>Email</TableHead><TableHead>Role</TableHead><TableHead>Status</TableHead><TableHead>Created</TableHead>{(canUpdate || canDelete) && <TableHead className="text-right"></TableHead>}</TableRow></TableHeader>
			<TableBody>{users.length === 0 ? (<TableRow><TableCell colSpan={(canUpdate || canDelete) ? 7 : 6} className="h-24 text-center"><span className="text-muted-foreground text-sm">No matching users found.</span></TableCell></TableRow>) : (
				users.map((user) => (<TableRow key={user.id} className="group transition-colors">
					<TableCell className="font-medium">{user.name}</TableCell>
					<TableCell>
						<div className="flex items-center gap-1">
							<code className="text-muted-foreground font-mono text-xs" title={user.id}>{formatUserId(user.id)}</code>
							<Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => copyUserId(user.id)} aria-label={`Copy user ID for ${user.email}`}>
								<Copy className="h-3 w-3" />
							</Button>
						</div>
					</TableCell><TableCell>{user.email}</TableCell>
					<TableCell><Badge variant="secondary">{user.role}</Badge></TableCell>
					<TableCell><Badge variant={user.is_active ? "outline" : "secondary"}>{user.is_active ? "Active" : "Inactive"}</Badge></TableCell>
					<TableCell className="text-muted-foreground text-sm">{new Date(user.created_at).toLocaleDateString()}</TableCell>
					{(canUpdate || canDelete) && (<TableCell className="text-right"><div className="flex items-center justify-end gap-1">
						{canUpdate && <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => { setEditingUser(user); setFormData({ email: user.email, name: user.name, password: "", role: user.role }); setError(""); setDialogOpen(true); }}><Edit className="h-4 w-4" /></Button>}
						{canDelete && <AlertDialog><AlertDialogTrigger asChild><Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:bg-destructive/10 hover:text-destructive border-destructive/30"><Trash2 className="h-4 w-4" /></Button></AlertDialogTrigger><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Delete User</AlertDialogTitle><AlertDialogDescription>Are you sure you want to delete &quot;{user.name}&quot;?</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Cancel</AlertDialogCancel><AlertDialogAction onClick={() => handleDelete(user)}>Delete</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>}
					</div></TableCell>)}
				</TableRow>))
			)}</TableBody></Table></div>
		{total > 0 && <div className="flex items-center justify-between px-2"><p className="text-muted-foreground text-sm">Showing {offset + 1}-{Math.min(offset + PAGE_SIZE, total)} of {total}</p><div className="flex gap-2"><Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}><ChevronLeft className="mr-1 h-4 w-4" /> Previous</Button><Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>Next <ChevronRight className="ml-1 h-4 w-4" /></Button></div></div>}
		{renderDialog()}
	</div>);
}
