import { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';
import { HandleLogin } from './login';
import { HandleLogout } from './logout';
import { HandleCallback } from './callback';
import { HandleProfile } from './profile';
import { HandlerError } from '../utils/errors';
/**
 * If you want to add some custom behavior to the default auth handlers, you can pass in custom handlers for
 * `login`, `logout`, `callback`, and `profile`. For example:
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 * import { errorReporter, logger } from '../../../utils';
 *
 * export default handleAuth({
 *   async login(req, res) {
 *     try {
 *        // Pass in custom params to your handler
 *       await handleLogin(req, res, { authorizationParams: { customParam: 'foo' } });
 *       // Add your own custom logging.
 *       logger('Redirecting to login');
 *     } catch (error) {
 *       // Add you own custom error logging.
 *       errorReporter(error);
 *       res.status(error.status || 500).end();
 *     }
 *   }
 * });
 * ```
 *
 * Alternatively, you can customize the default handlers without overriding them. For example:
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   login: handleLogin({
 *     authorizationParams: { customParam: 'foo' } // Pass in custom params
 *   })
 * });
 * ```
 *
 * You can also create new handlers by customizing the default ones. For example:
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth({
 *   signup: handleLogin({
 *     authorizationParams: { screen_hint: 'signup' }
 *   })
 * });
 * ```
 *
 * @category Server
 */
export type Handlers = ApiHandlers | ErrorHandlers;
type ApiHandlers = {
    [key: string]: NextApiHandler;
};
type ErrorHandlers = {
    onError?: OnError;
};
/**
 * The main way to use the server SDK.
 *
 * Simply set the environment variables per {@link ConfigParameters} then create the file
 * `pages/api/auth/[...auth0].js`. For example:
 *
 * ```js
 * // pages/api/auth/[...auth0].js
 * import { handleAuth } from '@auth0/nextjs-auth0';
 *
 * export default handleAuth();
 * ```
 *
 * This will create 5 handlers for the following urls:
 *
 * - `/api/auth/login`: log the user in to your app by redirecting them to your identity provider.
 * - `/api/auth/callback`: The page that your identity provider will redirect the user back to on login.
 * - `/api/auth/logout`: log the user out of your app.
 * - `/api/auth/me`: View the user profile JSON (used by the {@link UseUser} hook).
 * - `/api/auth/unauthorized`: Returns a 401 for use by {@link WithMiddlewareAuthRequired} when protecting API routes.
 *
 * @category Server
 */
export type HandleAuth = (userHandlers?: Handlers) => NextApiHandler;
/**
 * Error handler for the default auth routes.
 *
 * Use this to define an error handler for all the default routes in a single place. For example:
 *
 * ```js
 * export default handleAuth({
 *   onError(req, res, error) {
 *     errorLogger(error);
 *     // You can finish the response yourself if you want to customize
 *     // the status code or redirect the user
 *     // res.writeHead(302, {
 *     //     Location: '/custom-error-page'
 *     // });
 *     // res.end();
 *   }
 * });
 * ```
 *
 * @category Server
 */
export type OnError = (req: NextApiRequest, res: NextApiResponse, error: HandlerError) => Promise<void> | void;
/**
 * @ignore
 */
export default function handlerFactory({ handleLogin, handleLogout, handleCallback, handleProfile }: {
    handleLogin: HandleLogin;
    handleLogout: HandleLogout;
    handleCallback: HandleCallback;
    handleProfile: HandleProfile;
}): HandleAuth;
export {};
//# sourceMappingURL=auth.d.ts.map