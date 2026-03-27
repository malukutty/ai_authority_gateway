import crypto from "node:crypto";

function shortHash(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex").slice(0, 4);
}

export function maskAgentId(agentId: string): string {
  return `agent_${shortHash(agentId)}`;
}

export function maskTaskId(taskId: string): string {
  return `task_${shortHash(taskId)}`;
}

export function maskUserId(userId: string): string {
  return `user_${shortHash(userId)}`;
}

export function maskTeamId(teamId: string): string {
  return `team_${shortHash(teamId)}`;
}