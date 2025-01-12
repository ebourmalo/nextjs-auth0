import { NextRequest, NextResponse } from 'next/server';
import Session from './session/session';
import { WithMiddlewareAuthRequired } from './helpers/with-middleware-auth-required';
import { ConfigParameters } from './config';
export type Auth0Edge = {
    withMiddlewareAuthRequired: WithMiddlewareAuthRequired;
    getSession: GetSession;
    createSession: CreateSession;
};
export type GetSession = (req: NextRequest, res: NextResponse) => Promise<Session | null | undefined>;
export type CreateSession = (req: NextRequest, res: NextResponse, profile: Record<string, unknown>) => Promise<void>;
export type InitAuth0 = (params?: ConfigParameters) => Auth0Edge;
export { WithMiddlewareAuthRequired };
export declare const initAuth0: InitAuth0;
export declare const getSession: GetSession;
export declare const createSession: CreateSession;
export declare const withMiddlewareAuthRequired: WithMiddlewareAuthRequired;
//# sourceMappingURL=edge.d.ts.map