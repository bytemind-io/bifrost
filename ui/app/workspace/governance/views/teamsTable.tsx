"use client";

import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
	AlertDialogTrigger,
} from "@/components/ui/alertDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { resetDurationLabels } from "@/lib/constants/governance";
import { getErrorMessage, useDeleteTeamMutation } from "@/lib/store";
import { Customer, Team, VirtualKey } from "@/lib/types/governance";
import { cn } from "@/lib/utils";
import { formatCurrency } from "@/lib/utils/governance";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { Input } from "@/components/ui/input";
import { ChevronLeft, ChevronRight, Copy, Edit, Plus, Search, Trash2, Users } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import TeamDialog from "./teamDialog";
import { TeamsEmptyState } from "./teamsEmptyState";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";

interface TeamMember {
	id: string;
	name: string;
	email: string;
	role: string;
	is_active: boolean;
}

const formatUserId = (id: string) => id.length > 12 ? `${id.slice(0, 8)}...${id.slice(-4)}` : id;

function TeamMembersDialog({ teamId, teamName, open, onOpenChange }: { teamId: string; teamName: string; open: boolean; onOpenChange: (open: boolean) => void }) {
	const [members, setMembers] = useState<TeamMember[]>([]);
	const [allUsers, setAllUsers] = useState<TeamMember[]>([]);
	const [isLoading, setIsLoading] = useState(true);
	const [addDialogOpen, setAddDialogOpen] = useState(false);
	const [selectedUserId, setSelectedUserId] = useState("");
	const [userSearch, setUserSearch] = useState("");
	const [isSaving, setIsSaving] = useState(false);
	const hasUpdateAccess = useRbac(RbacResource.Teams, RbacOperation.Update);
	const { copy: copyUserId } = useCopyToClipboard({ successMessage: "User ID copied" });

	const fetchMembers = useCallback(async () => {
		if (!open) return;
		setIsLoading(true);
		try {
			const res = await fetch(`/api/enterprise/teams/${teamId}/members`, { credentials: "include" });
			if (res.ok) { const data = await res.json(); setMembers(data.data || []); }
		} catch { /* ignore */ } finally { setIsLoading(false); }
	}, [teamId, open]);

	useEffect(() => { fetchMembers(); }, [fetchMembers]);

	const fetchUsers = useCallback(async () => {
		try {
			const res = await fetch("/api/enterprise/users?limit=200", { credentials: "include" });
			if (res.ok) {
				const data = await res.json();
				const users = data.data || data.users || data || [];
				setAllUsers(Array.isArray(users) ? users : []);
			}
		} catch { /* ignore */ }
	}, []);

	useEffect(() => { if (addDialogOpen) fetchUsers(); }, [addDialogOpen, fetchUsers]);

	const memberIds = new Set(members.map((m) => m.id));
	const availableUsers = allUsers
		.filter((u) => !memberIds.has(u.id) && u.is_active)
		.filter((u) => {
			if (!userSearch.trim()) return true;
			const q = userSearch.toLowerCase();
			return u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q);
		});

	const handleAssign = async () => {
		if (!selectedUserId) return;
		setIsSaving(true);
		try {
			const res = await fetch(`/api/enterprise/teams/${teamId}/members`, {
				method: "POST", headers: { "Content-Type": "application/json" }, credentials: "include",
				body: JSON.stringify({ user_id: selectedUserId }),
			});
			if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error?.message || d.message || "Failed"); }
			toast.success("Member added"); setAddDialogOpen(false); setSelectedUserId(""); setUserSearch(""); fetchMembers();
		} catch (err: any) { toast.error(err.message); } finally { setIsSaving(false); }
	};

	const handleRemove = async (member: TeamMember) => {
		if (!confirm(`Remove "${member.name}" from team?`)) return;
		try {
			const res = await fetch(`/api/enterprise/teams/${teamId}/members/${member.id}`, { method: "DELETE", credentials: "include" });
			if (res.ok) { toast.success("Member removed"); fetchMembers(); }
		} catch { toast.error("Failed to remove member"); }
	};

	return (
		<>
			<Dialog open={open} onOpenChange={onOpenChange}>
				<DialogContent className="max-w-lg">
					<DialogHeader>
						<DialogTitle>Team Members: {teamName}</DialogTitle>
						<DialogDescription>Manage users in this team.</DialogDescription>
					</DialogHeader>
					<div className="space-y-3 py-2">
						{isLoading ? <p className="text-muted-foreground text-sm text-center py-4">Loading...</p>
						: members.length === 0 ? <p className="text-muted-foreground text-sm text-center py-4">No members in this team</p>
						: members.map((m) => (
							<div key={m.id} className="flex items-center justify-between rounded-sm border px-3 py-2">
								<div>
									<p className="text-sm font-medium">{m.name}</p>
									<p className="text-muted-foreground text-xs">{m.email}</p>
									<div className="mt-1 flex items-center gap-1">
										<code className="text-muted-foreground font-mono text-[11px]" title={m.id}>{formatUserId(m.id)}</code>
										<Button variant="ghost" size="icon" className="h-5 w-5" onClick={() => copyUserId(m.id)} aria-label={`Copy user ID for ${m.email}`}>
											<Copy className="h-3 w-3" />
										</Button>
									</div>
								</div>
								<div className="flex items-center gap-2">
									<Badge variant="outline" className="text-xs">{m.role}</Badge>
									{hasUpdateAccess && <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:bg-destructive/10 hover:text-destructive" onClick={() => handleRemove(m)}><Trash2 className="h-3 w-3" /></Button>}
								</div>
							</div>
						))}
					</div>
					<DialogFooter>
						{hasUpdateAccess && <Button size="sm" variant="outline" onClick={() => { setSelectedUserId(""); setUserSearch(""); setAddDialogOpen(true); }}><Plus className="mr-1 h-3 w-3" /> Add Member</Button>}
						<Button size="sm" onClick={() => onOpenChange(false)}>Close</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>

			<Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
				<DialogContent>
					<DialogHeader><DialogTitle>Add Member</DialogTitle><DialogDescription>Select a user to add to this team.</DialogDescription></DialogHeader>
					<div className="space-y-3 py-2">
						<Input value={userSearch} onChange={(e) => setUserSearch(e.target.value)} placeholder="Search by name or email..." />
						<div className="max-h-[240px] overflow-y-auto space-y-1 rounded-sm border p-1">
							{availableUsers.length === 0 ? (
								<p className="text-muted-foreground text-sm text-center py-4">{allUsers.length === 0 ? "Loading users..." : "No available users"}</p>
							) : availableUsers.map((u) => (
								<button
									key={u.id}
									type="button"
									className={`flex w-full items-center justify-between rounded-sm px-3 py-2 text-left text-sm transition-colors hover:bg-accent ${selectedUserId === u.id ? "bg-accent ring-1 ring-primary" : ""}`}
									onClick={() => setSelectedUserId(u.id)}
								>
									<div>
										<p className="font-medium">{u.name}</p>
										<p className="text-muted-foreground text-xs">{u.email}</p>
										<div className="mt-1 flex items-center gap-1">
											<code className="text-muted-foreground font-mono text-[11px]" title={u.id}>{formatUserId(u.id)}</code>
											<Button
												type="button"
												variant="ghost"
												size="icon"
												className="h-5 w-5"
												onClick={(e) => {
													e.stopPropagation();
													copyUserId(u.id);
												}}
												aria-label={`Copy user ID for ${u.email}`}
											>
												<Copy className="h-3 w-3" />
											</Button>
										</div>
									</div>
									<Badge variant="outline" className="text-xs">{u.role}</Badge>
								</button>
							))}
						</div>
					</div>
					<DialogFooter><Button variant="outline" onClick={() => setAddDialogOpen(false)}>Cancel</Button><Button onClick={handleAssign} disabled={isSaving || !selectedUserId}>{isSaving ? "Adding..." : "Add"}</Button></DialogFooter>
				</DialogContent>
			</Dialog>
		</>
	);
}

// Helper to format reset duration for display
const formatResetDuration = (duration: string) => {
	return resetDurationLabels[duration] || duration;
};

interface TeamsTableProps {
	teams: Team[];
	totalCount: number;
	customers: Customer[];
	virtualKeys: VirtualKey[];
	search: string;
	debouncedSearch: string;
	onSearchChange: (value: string) => void;
	offset: number;
	limit: number;
	onOffsetChange: (offset: number) => void;
}

export default function TeamsTable({ teams, totalCount, customers, virtualKeys, search, debouncedSearch, onSearchChange, offset, limit, onOffsetChange }: TeamsTableProps) {
	const [showTeamDialog, setShowTeamDialog] = useState(false);
	const [editingTeam, setEditingTeam] = useState<Team | null>(null);
	const [membersTeam, setMembersTeam] = useState<Team | null>(null);

	const hasCreateAccess = useRbac(RbacResource.Teams, RbacOperation.Create);
	const hasUpdateAccess = useRbac(RbacResource.Teams, RbacOperation.Update);
	const hasDeleteAccess = useRbac(RbacResource.Teams, RbacOperation.Delete);

	const [deleteTeam, { isLoading: isDeleting }] = useDeleteTeamMutation();

	const handleDelete = async (teamId: string) => {
		try {
			await deleteTeam(teamId).unwrap();
			toast.success("Team deleted successfully");
		} catch (error) {
			toast.error(getErrorMessage(error));
		}
	};

	const handleAddTeam = () => {
		setEditingTeam(null);
		setShowTeamDialog(true);
	};

	const handleEditTeam = (team: Team) => {
		setEditingTeam(team);
		setShowTeamDialog(true);
	};

	const handleTeamSaved = () => {
		setShowTeamDialog(false);
		setEditingTeam(null);
	};

	const getVirtualKeysForTeam = (teamId: string) => {
		return virtualKeys.filter((vk) => vk.team_id === teamId);
	};

	const getCustomerName = (customerId?: string) => {
		if (!customerId) return "-";
		const customer = customers.find((c) => c.id === customerId);
		return customer ? customer.name : "Unknown Customer";
	};

	const hasActiveFilters = debouncedSearch;

	// True empty state: no teams at all (not just filtered to zero)
	if (totalCount === 0 && !hasActiveFilters) {
		return (
			<>
				<TooltipProvider>
					{showTeamDialog && (
						<TeamDialog team={editingTeam} customers={customers} onSave={handleTeamSaved} onCancel={() => setShowTeamDialog(false)} />
					)}
					<TeamsEmptyState onAddClick={handleAddTeam} canCreate={hasCreateAccess} />
				</TooltipProvider>
			</>
		);
	}

	return (
		<>
			<TooltipProvider>
				{showTeamDialog && (
					<TeamDialog team={editingTeam} customers={customers} onSave={handleTeamSaved} onCancel={() => setShowTeamDialog(false)} />
				)}

				<div className="space-y-4">
					<div className="flex items-center justify-between">
						<div>
							<h2 className="text-lg font-semibold">Teams</h2>
							<p className="text-muted-foreground text-sm">Organize users into teams with shared budgets and access controls.</p>
						</div>
						<Button data-testid="create-team-btn" onClick={handleAddTeam} disabled={!hasCreateAccess}>
							<Plus className="h-4 w-4" />
							Add Team
						</Button>
					</div>

					<div className="flex items-center gap-3">
						<div className="relative max-w-sm flex-1">
							<Search className="text-muted-foreground absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2" />
							<Input
								aria-label="Search teams by name"
								placeholder="Search by name..."
								value={search}
								onChange={(e) => onSearchChange(e.target.value)}
								className="pl-9"
								data-testid="teams-search-input"
							/>
						</div>
					</div>

					<div className="rounded-sm border overflow-x-auto" data-testid="teams-table">
						<Table className="min-w-[1180px]">
							<TableHeader>
								<TableRow>
									<TableHead>Name</TableHead>
									<TableHead>Customer</TableHead>
									<TableHead>Budget</TableHead>
									<TableHead>Rate Limit</TableHead>
									<TableHead>Historical Usage</TableHead>
									<TableHead>Virtual Keys</TableHead>
									<TableHead className="text-right"></TableHead>
								</TableRow>
							</TableHeader>
							<TableBody>
								{teams.length === 0 ? (
									<TableRow>
										<TableCell colSpan={7} className="h-24 text-center">
											<span className="text-muted-foreground text-sm">No matching teams found.</span>
										</TableCell>
									</TableRow>
								) : (
								teams.map((team) => {
									const vks = getVirtualKeysForTeam(team.id);
									const customerName = getCustomerName(team.customer_id);

									// Budget calculations
									const isBudgetExhausted =
										team.budget?.max_limit && team.budget.max_limit > 0 && team.budget.current_usage >= team.budget.max_limit;
									const budgetPercentage =
										team.budget?.max_limit && team.budget.max_limit > 0
											? Math.min((team.budget.current_usage / team.budget.max_limit) * 100, 100)
											: 0;

									// Rate limit calculations
									const isTokenLimitExhausted =
										team.rate_limit?.token_max_limit &&
										team.rate_limit.token_max_limit > 0 &&
										team.rate_limit.token_current_usage >= team.rate_limit.token_max_limit;
									const isRequestLimitExhausted =
										team.rate_limit?.request_max_limit &&
										team.rate_limit.request_max_limit > 0 &&
										team.rate_limit.request_current_usage >= team.rate_limit.request_max_limit;
									const isRateLimitExhausted = isTokenLimitExhausted || isRequestLimitExhausted;
									const tokenPercentage =
										team.rate_limit?.token_max_limit && team.rate_limit.token_max_limit > 0
											? Math.min((team.rate_limit.token_current_usage / team.rate_limit.token_max_limit) * 100, 100)
											: 0;
									const requestPercentage =
										team.rate_limit?.request_max_limit && team.rate_limit.request_max_limit > 0
											? Math.min((team.rate_limit.request_current_usage / team.rate_limit.request_max_limit) * 100, 100)
											: 0;

									const isExhausted = isBudgetExhausted || isRateLimitExhausted;

									return (
										<TableRow key={team.id} data-testid={`team-row-${team.name}`} className={cn("group transition-colors", isExhausted && "bg-red-500/5 hover:bg-red-500/10")}>
											<TableCell className="max-w-[200px] py-4">
												<div className="flex flex-col gap-2">
													<span className="truncate font-medium">{team.name}</span>
													{isExhausted && (
														<Badge variant="destructive" className="w-fit text-xs">
															Limit Reached
														</Badge>
													)}
												</div>
											</TableCell>
											<TableCell data-testid={`team-row-${team.name}-customer`}>
												<div className="flex items-center gap-2">
													<Badge variant={team.customer_id ? "secondary" : "outline"}>{customerName}</Badge>
												</div>
											</TableCell>
											<TableCell className="min-w-[180px]">
												{team.budget ? (
													<Tooltip>
														<TooltipTrigger asChild>
															<div className="space-y-2">
																<div className="flex items-center justify-between gap-4">
																	<span className="font-medium">{formatCurrency(team.budget.max_limit)}</span>
																	<span className="text-muted-foreground text-xs">{formatResetDuration(team.budget.reset_duration)}</span>
																</div>
																<Progress
																	value={budgetPercentage}
																	className={cn(
																		"bg-muted/70 dark:bg-muted/30 h-1.5",
																		isBudgetExhausted
																			? "[&>div]:bg-red-500/70"
																			: budgetPercentage > 80
																				? "[&>div]:bg-amber-500/70"
																				: "[&>div]:bg-emerald-500/70",
																	)}
																/>
															</div>
														</TooltipTrigger>
														<TooltipContent>
															<p className="font-medium">
																{formatCurrency(team.budget.current_usage)} / {formatCurrency(team.budget.max_limit)}
															</p>
															<p className="text-primary-foreground/80 text-xs">Resets {formatResetDuration(team.budget.reset_duration)}</p>
														</TooltipContent>
													</Tooltip>
												) : (
													<span className="text-muted-foreground text-sm">-</span>
												)}
											</TableCell>
											<TableCell className="min-w-[180px]">
												{team.rate_limit ? (
													<div className="space-y-2.5">
														{team.rate_limit.token_max_limit && (
															<Tooltip>
																<TooltipTrigger asChild>
																	<div className="space-y-1.5">
																		<div className="flex items-center justify-between gap-4 text-xs">
																			<span className="font-medium">{team.rate_limit.token_max_limit.toLocaleString()} tokens</span>
																			<span className="text-muted-foreground">
																				{formatResetDuration(team.rate_limit.token_reset_duration || "1h")}
																			</span>
																		</div>
																		<Progress
																			value={tokenPercentage}
																			className={cn(
																				"bg-muted/70 dark:bg-muted/30 h-1",
																				isTokenLimitExhausted
																					? "[&>div]:bg-red-500/70"
																					: tokenPercentage > 80
																						? "[&>div]:bg-amber-500/70"
																						: "[&>div]:bg-emerald-500/70",
																			)}
																		/>
																	</div>
																</TooltipTrigger>
																<TooltipContent>
																	<p className="font-medium">
																		{team.rate_limit.token_current_usage.toLocaleString()} /{" "}
																		{team.rate_limit.token_max_limit.toLocaleString()} tokens
																	</p>
																	<p className="text-primary-foreground/80 text-xs">
																		Resets {formatResetDuration(team.rate_limit.token_reset_duration || "1h")}
																	</p>
																</TooltipContent>
															</Tooltip>
														)}
														{team.rate_limit.request_max_limit && (
															<Tooltip>
																<TooltipTrigger asChild>
																	<div className="space-y-1.5">
																		<div className="flex items-center justify-between gap-4 text-xs">
																			<span className="font-medium">{team.rate_limit.request_max_limit.toLocaleString()} req</span>
																			<span className="text-muted-foreground">
																				{formatResetDuration(team.rate_limit.request_reset_duration || "1h")}
																			</span>
																		</div>
																		<Progress
																			value={requestPercentage}
																			className={cn(
																				"bg-muted/70 dark:bg-muted/30 h-1",
																				isRequestLimitExhausted
																					? "[&>div]:bg-red-500/70"
																					: requestPercentage > 80
																						? "[&>div]:bg-amber-500/70"
																						: "[&>div]:bg-emerald-500/70",
																			)}
																		/>
																	</div>
																</TooltipTrigger>
																<TooltipContent>
																	<p className="font-medium">
																		{team.rate_limit.request_current_usage.toLocaleString()} /{" "}
																		{team.rate_limit.request_max_limit.toLocaleString()} requests
																	</p>
																	<p className="text-primary-foreground/80 text-xs">
																		Resets {formatResetDuration(team.rate_limit.request_reset_duration || "1h")}
																	</p>
																</TooltipContent>
															</Tooltip>
														)}
													</div>
												) : (
													<span className="text-muted-foreground text-sm">-</span>
												)}
											</TableCell>
											<TableCell className="min-w-[190px]">
												{team.historical_usage ? (
													<div className="space-y-1.5 text-sm">
														<div className="flex items-center justify-between gap-3">
															<span className="text-muted-foreground text-xs">Cost</span>
															<span className="font-medium">{formatCurrency(team.historical_usage.total_cost)}</span>
														</div>
														<div className="flex items-center justify-between gap-3">
															<span className="text-muted-foreground text-xs">Tokens</span>
															<span className="font-medium">{team.historical_usage.total_tokens.toLocaleString()}</span>
														</div>
														<div className="flex items-center justify-between gap-3">
															<span className="text-muted-foreground text-xs">Requests</span>
															<span className="font-medium">{team.historical_usage.total_requests.toLocaleString()}</span>
														</div>
													</div>
												) : (
													<span className="text-muted-foreground text-sm">-</span>
												)}
											</TableCell>
											<TableCell>
												{vks.length > 0 ? (
													<div className="flex items-center gap-2">
														<Tooltip>
															<TooltipTrigger>
																<Badge variant="outline" className="text-xs">
																	{vks.length} {vks.length === 1 ? "key" : "keys"}
																</Badge>
															</TooltipTrigger>
															<TooltipContent>{vks.map((vk) => vk.name).join(", ")}</TooltipContent>
														</Tooltip>
													</div>
												) : (
													<span className="text-muted-foreground text-sm">-</span>
												)}
											</TableCell>
											<TableCell className="text-right">
												<div className="flex items-center justify-end gap-1">
													<Button
														variant="ghost"
														size="icon"
														className="h-8 w-8"
														onClick={() => setMembersTeam(team)}
														aria-label={`Members of team ${team.name}`}
														data-testid={`team-members-btn-${team.name}`}
													>
														<Users className="h-4 w-4" />
													</Button>
													<Button
														variant="ghost"
														size="icon"
														className="h-8 w-8"
														onClick={() => handleEditTeam(team)}
														disabled={!hasUpdateAccess}
														aria-label={`Edit team ${team.name}`}
														data-testid={`team-edit-btn-${team.name}`}
													>
														<Edit className="h-4 w-4" />
													</Button>
													<AlertDialog>
														<AlertDialogTrigger asChild>
															<Button
																variant="ghost"
																size="icon"
																className="h-8 w-8 text-destructive hover:bg-destructive/10 hover:text-destructive border-destructive/30"
																disabled={!hasDeleteAccess}
																aria-label={`Delete team ${team.name}`}
																data-testid={`team-delete-btn-${team.name}`}
															>
																<Trash2 className="h-4 w-4" />
															</Button>
														</AlertDialogTrigger>
														<AlertDialogContent>
															<AlertDialogHeader>
																<AlertDialogTitle>Delete Team</AlertDialogTitle>
																<AlertDialogDescription>
																	Are you sure you want to delete &quot;{team.name}&quot;? This will also unassign any virtual keys from
																	this team. This action cannot be undone.
																</AlertDialogDescription>
															</AlertDialogHeader>
															<AlertDialogFooter>
																<AlertDialogCancel>Cancel</AlertDialogCancel>
																<AlertDialogAction
																	onClick={() => handleDelete(team.id)}
																	disabled={isDeleting}
																>
																	{isDeleting ? "Deleting..." : "Delete"}
																</AlertDialogAction>
															</AlertDialogFooter>
														</AlertDialogContent>
													</AlertDialog>
												</div>
											</TableCell>
										</TableRow>
									);
								})
								)}
							</TableBody>
						</Table>
					</div>

					{/* Pagination */}
					{totalCount > 0 && (
						<div className="flex items-center justify-between px-2">
							<p className="text-muted-foreground text-sm">
								Showing {offset + 1}-{Math.min(offset + limit, totalCount)} of {totalCount}
							</p>
							<div className="flex gap-2">
								<Button
									variant="outline"
									size="sm"
									disabled={offset === 0}
									onClick={() => onOffsetChange(Math.max(0, offset - limit))}
									data-testid="teams-pagination-prev-btn"
								>
									<ChevronLeft className="mr-1 h-4 w-4" /> Previous
								</Button>
								<Button
									variant="outline"
									size="sm"
									disabled={offset + limit >= totalCount}
									onClick={() => onOffsetChange(offset + limit)}
									data-testid="teams-pagination-next-btn"
								>
									Next <ChevronRight className="ml-1 h-4 w-4" />
								</Button>
							</div>
						</div>
					)}
				</div>

				{membersTeam && (
					<TeamMembersDialog
						teamId={membersTeam.id}
						teamName={membersTeam.name}
						open={!!membersTeam}
						onOpenChange={(open) => { if (!open) setMembersTeam(null); }}
					/>
				)}
			</TooltipProvider>
		</>
	);
}
