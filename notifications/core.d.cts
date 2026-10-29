export type NotificationInput = { event: string; key: string; reference: string; to?: string; code?: string };
export type Mail = { from: string; to: string; subject: string; text: string; messageId?: string };
export type Template = { audience: 'operator' | 'customer'; subject: string; path: string; code?: boolean; text: (input: NotificationInput) => string };
export type EligibilityPayload = Omit<NotificationInput, 'key'> & { from: string; to: string };
export type Options = { project: string; name: string; from: string; origin: string; templates: Record<string, Template>; env?: NodeJS.ProcessEnv; now?: () => number; eligible?: (payload: EligibilityPayload) => Promise<boolean>; send?: (mail: Mail) => Promise<{ accepted: string[]; rejected?: string[] }> };
export function createNotifications(options: Options): {
 mode: string; enqueue(input: NotificationInput): Promise<{status:string;id?:string;duplicate?:boolean}>;
 notify(input: NotificationInput): Promise<{status:string;id?:string;duplicate?:boolean}>;
 dispatch(): Promise<{status:string;id?:string}>; start(): void; health(): unknown; captures(): Mail[]; close(): Promise<void>; setEligibility(eligible: NonNullable<Options['eligible']>): void;
};
