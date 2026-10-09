import '@angular/compiler';

import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Subject, defer, firstValueFrom, of, throwError } from 'rxjs';

import { AuthService, TokenResponse } from './auth.service';

const TOKENS: TokenResponse = {
  access_token: 'access-1',
  refresh_token: 'refresh-1',
  token_type: 'Bearer',
  expires_in: 3600,
};

describe('AuthService', () => {
  let http: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };
  let service: AuthService;

  beforeEach(() => {
    localStorage.clear();
    http = {
      get: vi.fn(() => of({ auth_enabled: true, setup_required: false })),
      post: vi.fn(() => of(TOKENS)),
    };
    service = new AuthService(http as unknown as HttpClient);
  });

  it('queries the public authentication status endpoint', () => {
    service.checkAuth().subscribe();
    expect(http.get).toHaveBeenCalledWith('/api/auth/status');
  });

  it.each([
    ['setup', 'setup'],
    ['login', 'login'],
  ] as const)('%s posts credentials and stores returned tokens', (method, endpoint) => {
    service[method]('alice', 'secret').subscribe();

    expect(http.post).toHaveBeenCalledWith(`/api/auth/${endpoint}`, {
      username: 'alice',
      password: 'secret',
    });
    expect(service.getAccessToken()).toBe('access-1');
    expect(localStorage.getItem('refresh_token')).toBe('refresh-1');
  });

  it('refreshes with the persisted refresh token and rotates both tokens', () => {
    localStorage.setItem('refresh_token', 'old-refresh');
    service.refresh().subscribe();

    expect(http.post).toHaveBeenCalledWith('/api/auth/refresh', {
      refresh_token: 'old-refresh',
    });
    expect(localStorage.getItem('refresh_token')).toBe('refresh-1');
  });

  it('clears local credentials immediately when logging out', () => {
    localStorage.setItem('access_token', 'old-access');
    localStorage.setItem('refresh_token', 'old-refresh');
    service.logout().subscribe();

    expect(http.post).toHaveBeenCalledWith('/api/auth/logout', {
      refresh_token: 'old-refresh',
    });
    expect(service.isLoggedIn()).toBe(false);
    expect(localStorage.getItem('refresh_token')).toBeNull();
  });

  it('reports login state solely from the access token', () => {
    expect(service.isLoggedIn()).toBe(false);
    localStorage.setItem('refresh_token', 'refresh-only');
    expect(service.isLoggedIn()).toBe(false);
    localStorage.setItem('access_token', 'access');
    expect(service.isLoggedIn()).toBe(true);
  });

  it('shares one in-flight refresh between concurrent callers', () => {
    const response = new Subject<TokenResponse>();
    http.post.mockReturnValue(response);
    localStorage.setItem('refresh_token', 'old-refresh');

    const received: string[] = [];
    service.refresh().subscribe((t) => received.push(t.access_token));
    service.refresh().subscribe((t) => received.push(t.access_token));
    response.next(TOKENS);
    response.complete();

    expect(http.post).toHaveBeenCalledTimes(1);
    expect(received).toEqual(['access-1', 'access-1']);
  });

  it('does not treat a stored token as authenticated until the server confirms it', async () => {
    localStorage.setItem('access_token', 'stored');
    service = new AuthService(http as unknown as HttpClient);
    expect(service.authenticated()).toBe(false);

    await expect(firstValueFrom(service.ensureSession())).resolves.toBe(true);

    expect(http.get).toHaveBeenCalledWith('/api/status');
    expect(service.authenticated()).toBe(true);
  });

  it('clears a stored token the server rejects', async () => {
    localStorage.setItem('access_token', 'stale');
    localStorage.setItem('refresh_token', 'stale-refresh');
    service = new AuthService(http as unknown as HttpClient);
    http.get.mockReturnValue(throwError(() => new HttpErrorResponse({ status: 401 })));

    await expect(firstValueFrom(service.ensureSession())).resolves.toBe(false);

    expect(service.isLoggedIn()).toBe(false);
    expect(service.authenticated()).toBe(false);
    expect(localStorage.getItem('refresh_token')).toBeNull();
  });

  it('refreshes up front instead of probing with a known-expired token', async () => {
    localStorage.setItem('access_token', 'expired');
    localStorage.setItem('refresh_token', 'old-refresh');
    localStorage.setItem('access_token_expires_at', String(Date.now() - 1000));
    service = new AuthService(http as unknown as HttpClient);

    await expect(firstValueFrom(service.ensureSession())).resolves.toBe(true);

    expect(http.get).not.toHaveBeenCalled();
    expect(http.post).toHaveBeenCalledWith('/api/auth/refresh', { refresh_token: 'old-refresh' });
    expect(service.getAccessToken()).toBe('access-1');
  });

  it('reports no session without contacting the server when no token is stored', async () => {
    await expect(firstValueFrom(service.ensureSession())).resolves.toBe(false);
    expect(http.get).not.toHaveBeenCalled();
  });

  it('marks the session authenticated immediately after login', () => {
    service.login('alice', 'secret').subscribe();
    expect(service.authenticated()).toBe(true);
    service.clearTokens();
    expect(service.authenticated()).toBe(false);
  });

  describe('cross-tab refresh (BUG-123)', () => {
    const rejected = () => new HttpErrorResponse({ status: 401 });
    /** Simulates another tab finishing its refresh: it writes localStorage. */
    function otherTabStores(access: string, refresh: string, notify = false): void {
      localStorage.setItem('access_token', access);
      localStorage.setItem('refresh_token', refresh);
      if (notify) {
        window.dispatchEvent(new StorageEvent('storage', { key: 'refresh_token', newValue: refresh }));
      }
    }

    beforeEach(() => {
      localStorage.setItem('access_token', 'old-access');
      localStorage.setItem('refresh_token', 'old-refresh');
      service = new AuthService(http as unknown as HttpClient);
    });

    afterEach(() => vi.useRealTimers());

    it('adopts tokens another tab already rotated instead of failing', async () => {
      // Both tabs spent old-refresh; the other tab won and stored its result
      // before this tab's rejection came back.
      http.post.mockReturnValue(
        defer(() => {
          otherTabStores('tab-b-access', 'tab-b-refresh');
          return throwError(rejected);
        }),
      );

      const tokens = await firstValueFrom(service.refresh());

      expect(tokens.access_token).toBe('tab-b-access');
      expect(service.getAccessToken()).toBe('tab-b-access');
      expect(localStorage.getItem('refresh_token')).toBe('tab-b-refresh');
    });

    it('waits briefly for a refresh still in flight in another tab', async () => {
      const response = new Subject<TokenResponse>();
      http.post.mockReturnValue(response);
      const result = firstValueFrom(service.refresh());

      response.error(rejected());
      otherTabStores('tab-b-access', 'tab-b-refresh', true);

      await expect(result).resolves.toMatchObject({ access_token: 'tab-b-access' });
      expect(localStorage.getItem('refresh_token')).toBe('tab-b-refresh');
    });

    it('still fails when no other tab rotated the tokens', async () => {
      vi.useFakeTimers();
      http.post.mockReturnValue(throwError(rejected));
      const result = firstValueFrom(service.refresh());
      const outcome = expect(result).rejects.toMatchObject({ status: 401 });
      await vi.advanceTimersByTimeAsync(10_000);
      await outcome;
      expect(service.discardFailedSession()).toBe(true);
      expect(localStorage.getItem('access_token')).toBeNull();
    });

    it('keeps a session another tab replaced while the probe was rejected', async () => {
      http.get.mockReturnValue(
        defer(() => {
          otherTabStores('tab-b-access', 'tab-b-refresh');
          return throwError(rejected);
        }),
      );

      await expect(firstValueFrom(service.ensureSession())).resolves.toBe(true);
      expect(service.getAccessToken()).toBe('tab-b-access');
    });

    it('only clears tokens that are still the ones that failed', async () => {
      vi.useFakeTimers();
      http.post.mockReturnValue(throwError(rejected));
      const result = firstValueFrom(service.refresh());
      const outcome = expect(result).rejects.toMatchObject({ status: 401 });
      await vi.advanceTimersByTimeAsync(10_000);
      await outcome;
      // Another tab logged in / refreshed after this tab gave up waiting.
      otherTabStores('tab-b-access', 'tab-b-refresh');

      expect(service.discardFailedSession()).toBe(false);
      expect(service.getAccessToken()).toBe('tab-b-access');
      expect(localStorage.getItem('refresh_token')).toBe('tab-b-refresh');
    });
  });
});
