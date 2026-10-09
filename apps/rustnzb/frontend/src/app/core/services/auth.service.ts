import { Injectable, computed, signal } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import {
  Observable,
  catchError,
  filter,
  finalize,
  fromEvent,
  map,
  of,
  shareReplay,
  take,
  tap,
  throwError,
  timeout,
} from 'rxjs';

export interface AuthStatus {
  auth_enabled: boolean;
  setup_required: boolean;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

const ACCESS_KEY = 'access_token';
const REFRESH_KEY = 'refresh_token';
const EXPIRES_KEY = 'access_token_expires_at';
// Refresh slightly early so a token never expires between check and use.
const EXPIRY_SKEW_MS = 30_000;
// How long a rejected refresh waits for another tab, which may have spent the
// same single-use refresh token first, to store the rotated tokens.
const CROSS_TAB_REFRESH_GRACE_MS = 5_000;

@Injectable({ providedIn: 'root' })
export class AuthService {
  private baseUrl = '/api/auth';

  private readonly accessToken = signal<string | null>(localStorage.getItem(ACCESS_KEY));
  // A stored token is only a claim: the server keeps tokens in memory, so a
  // restart (or expiry) invalidates it. Chrome and guarded routes wait until
  // the token has been confirmed against the server once per page load.
  private readonly verified = signal(false);
  readonly authenticated = computed(() => !!this.accessToken() && this.verified());

  private refresh$: Observable<TokenResponse> | null = null;
  /** Refresh token spent by this tab's most recent refresh attempt. */
  private lastSpentRefresh: string | null = null;
  private verify$: Observable<boolean> | null = null;

  constructor(private http: HttpClient) {}

  checkAuth(): Observable<AuthStatus> {
    return this.http.get<AuthStatus>(`${this.baseUrl}/status`);
  }

  setup(username: string, password: string): Observable<TokenResponse> {
    return this.http
      .post<TokenResponse>(`${this.baseUrl}/setup`, { username, password })
      .pipe(tap((res) => this.storeTokens(res)));
  }

  login(username: string, password: string): Observable<TokenResponse> {
    return this.http
      .post<TokenResponse>(`${this.baseUrl}/login`, { username, password })
      .pipe(tap((res) => this.storeTokens(res)));
  }

  /**
   * Rotate tokens. Concurrent callers share one in-flight request: refresh
   * tokens are single-use, so parallel refreshes would revoke each other.
   *
   * Other tabs share localStorage but not this in-flight request, so two tabs
   * can spend the same refresh token. The loser's rejection is not a dead
   * session when the winner has stored (or shortly stores) newer tokens:
   * adopt those instead of failing.
   */
  refresh(): Observable<TokenResponse> {
    if (!this.refresh$) {
      const refreshToken = localStorage.getItem(REFRESH_KEY);
      this.lastSpentRefresh = refreshToken;
      this.refresh$ = this.http
        .post<TokenResponse>(`${this.baseUrl}/refresh`, { refresh_token: refreshToken })
        .pipe(
          tap((res) => this.storeTokens(res)),
          catchError((err) => this.adoptTokensRotatedElsewhere(refreshToken, err)),
          finalize(() => (this.refresh$ = null)),
          shareReplay({ bufferSize: 1, refCount: false }),
        );
    }
    return this.refresh$;
  }

  /**
   * After a failed refresh: clear the session only if the stored refresh
   * token is still the one that failed. Returns false when another tab has
   * stored newer tokens in the meantime (callers should retry with those).
   */
  discardFailedSession(): boolean {
    const stored = localStorage.getItem(REFRESH_KEY);
    if (stored && stored !== this.lastSpentRefresh && this.getAccessToken()) {
      this.accessToken.set(this.getAccessToken());
      return false;
    }
    this.clearTokens();
    return true;
  }

  private adoptTokensRotatedElsewhere(spent: string | null, err: unknown): Observable<TokenResponse> {
    const rejected =
      err instanceof HttpErrorResponse && (err.status === 401 || err.status === 403);
    if (!rejected) return throwError(() => err);
    const stored = this.rotatedTokens(spent);
    if (stored) return of(stored);
    if (typeof window === 'undefined') return throwError(() => err);
    // The other tab's refresh may still be in flight: its write fires a
    // 'storage' event here (storeTokens writes the access token first).
    return fromEvent<StorageEvent>(window, 'storage').pipe(
      map(() => this.rotatedTokens(spent)),
      filter((tokens): tokens is TokenResponse => tokens !== null),
      take(1),
      timeout({ first: CROSS_TAB_REFRESH_GRACE_MS, with: () => throwError(() => err) }),
    );
  }

  /** Tokens in storage if they differ from the refresh token we spent. */
  private rotatedTokens(spent: string | null): TokenResponse | null {
    const access = localStorage.getItem(ACCESS_KEY);
    const refresh = localStorage.getItem(REFRESH_KEY);
    if (!access || !refresh || refresh === spent) return null;
    this.accessToken.set(access);
    this.verified.set(true);
    const expiresAt = Number(localStorage.getItem(EXPIRES_KEY));
    return {
      access_token: access,
      refresh_token: refresh,
      token_type: 'Bearer',
      expires_in: expiresAt ? Math.max(0, Math.floor((expiresAt - Date.now()) / 1000)) : 0,
    };
  }

  logout(): Observable<void> {
    const refreshToken = localStorage.getItem(REFRESH_KEY);
    this.clearTokens();
    return this.http.post<void>(`${this.baseUrl}/logout`, { refresh_token: refreshToken });
  }

  /**
   * Resolve whether the stored session is usable, confirming it with the
   * server on first use. Emits false (and clears tokens) when the server
   * rejects it; a network failure leaves the session in place.
   */
  ensureSession(): Observable<boolean> {
    if (!this.getAccessToken()) return of(false);
    if (this.verified()) return of(true);
    if (!this.verify$) {
      const probed = this.getAccessToken();
      const probe$: Observable<unknown> = this.accessTokenExpired()
        ? this.refresh()
        : this.http.get('/api/status');
      this.verify$ = probe$.pipe(
        map(() => true),
        catchError((err) => {
          const rejected =
            err instanceof HttpErrorResponse && (err.status === 401 || err.status === 403);
          // Another tab may have replaced the rejected tokens meanwhile.
          const replaced = this.getAccessToken() !== probed;
          if (rejected && !replaced) this.clearTokens();
          return of(!rejected || replaced);
        }),
        map((ok) => ok && this.isLoggedIn()),
        tap((ok) => this.verified.set(ok)),
        finalize(() => (this.verify$ = null)),
        shareReplay({ bufferSize: 1, refCount: false }),
      );
    }
    return this.verify$;
  }

  isLoggedIn(): boolean {
    return !!localStorage.getItem(ACCESS_KEY);
  }

  getAccessToken(): string | null {
    return localStorage.getItem(ACCESS_KEY);
  }

  private accessTokenExpired(): boolean {
    const expiresAt = Number(localStorage.getItem(EXPIRES_KEY));
    return !!expiresAt && Date.now() >= expiresAt - EXPIRY_SKEW_MS;
  }

  private storeTokens(res: TokenResponse): void {
    localStorage.setItem(ACCESS_KEY, res.access_token);
    localStorage.setItem(REFRESH_KEY, res.refresh_token);
    if (res.expires_in) {
      localStorage.setItem(EXPIRES_KEY, String(Date.now() + res.expires_in * 1000));
    }
    this.accessToken.set(res.access_token);
    this.verified.set(true);
  }

  clearTokens(): void {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(EXPIRES_KEY);
    this.accessToken.set(null);
    this.verified.set(false);
  }
}
