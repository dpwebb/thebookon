import { createNotifications, type Options } from './core.cjs';
export const notifications: ReturnType<typeof createNotifications>;
export function createProjectNotifications(overrides?: Partial<Options>): ReturnType<typeof createNotifications>;
