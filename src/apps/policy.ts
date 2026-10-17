export function canAccess(
  user: { isActive: boolean },
  userGroupIds: readonly string[],
  app: { allowedGroupIds: readonly string[] },
): boolean {
  if (!user.isActive) return false;
  if (app.allowedGroupIds.length === 0) return true;
  return app.allowedGroupIds.some((id) => userGroupIds.includes(id));
}
