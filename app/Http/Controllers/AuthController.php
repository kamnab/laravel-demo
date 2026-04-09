<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

class AuthController extends Controller
{
    /* ----------------------------------------
     | Inline OAUTH Configuration
     |-----------------------------------------*/
    private array $oauth = [
        'issuer' => 'https://localhost:44313',
        'client_id' => 'php-demo-id',
        'client_secret' => 'php-demo-secret',
        'redirect_uri' => 'https://laravel-demo.test/callback/login/local',
        'scope' => 'openid profile email php-demo-services',
    ];

    /* ----------------------------------------
     | Helpers
     |-----------------------------------------*/
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function oauthUrl(string $path): string
    {
        return rtrim($this->oauth['issuer'], '/') . $path;
    }

    /* ----------------------------------------
     | Step 1: Redirect to OAUTH Server
     |-----------------------------------------*/
    public function login()
    {
        $state = Str::random(40);
        $verifier = Str::random(64);

        session([
            'oauth_state' => $state,
            'pkce_verifier' => $verifier,
        ]);

        $challenge = $this->base64UrlEncode(
            hash('sha256', $verifier, true)
        );

        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauth['client_id'],
            'redirect_uri' => $this->oauth['redirect_uri'],
            'state' => $state,
            'scope' => $this->oauth['scope'],
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]);

        return redirect(
            $this->oauthUrl('/connect/authorize') . '?' . $query
        );
    }

    /* ----------------------------------------
     | Step 2: Handle callback
     |-----------------------------------------*/
    public function callback(Request $request)
    {
        abort_if(
            !$request->has('state') ||
            $request->state !== session('oauth_state'),
            403,
            'Invalid state'
        );

        $response = Http::withoutVerifying()->asForm()->post(
            $this->oauthUrl('/connect/token'),
            [
                'grant_type' => 'authorization_code',
                'client_id' => $this->oauth['client_id'],
                'client_secret' => $this->oauth['client_secret'],
                'redirect_uri' => $this->oauth['redirect_uri'],
                'code' => $request->code,
                'code_verifier' => session('pkce_verifier'),
            ]
        );

        abort_if(!$response->successful(), 500, $response->body());

        $tokens = $response->json();

        // ✅ Extract SID from id_token
        $sid = null;
        $id_token = $tokens['id_token'] ?? null;
        if ($id_token) {
            $parts = explode('.', $id_token);

            if (count($parts) === 3) {
                $payload = json_decode(base64_decode($parts[1]), true);
                $sid = $payload['sid'] ?? null;
            }
        }

        /* Decode JWT claims */
        // $payload = explode('.', $id_token)[1];
        // $claims = json_decode(base64_decode($payload), true);
        // return view('dashboard', ['userInfo' => $claims]);

        // 👉 Get user info
        $userInfo = Http::withoutVerifying()->withToken($tokens['access_token'])
            ->get($this->oauthUrl('/connect/userinfo'))
            ->json();

        // 👉 Safe email fallback
        $email = $userInfo['email'] ?? ($userInfo['sub'] . '@local');

        // 👉 Create or update user
        $user = \App\Models\User::updateOrCreate(
            ['email' => $email],
            [
                'name' => $userInfo['name'] ?? $userInfo['preferred_username'] ?? 'Unknown',
                'password' => bcrypt(Str::random(16)),
            ]
        );

        // 👉 Login user
        Auth::login($user);

        // 🔐 Regenerate session AFTER login
        $request->session()->regenerate();

        // /api/backchannel-logout can not use session('sid') as it is not sent by browser, 
        // so we need to store sid in cache with sub mapping
        // ✅ Store SID mapping
        if ($sid) {
            Cache::put("sid_$sid", $userInfo['sub'], now()->addHours(2));
        }

        // 👉 Store tokens securely
        session([
            'access_token' => $tokens['access_token'],
            'id_token' => $tokens['id_token'] ?? null,
            // Store sid for front-channel logout in routes/web.php
            'sid' => $sid,
        ]);

        return redirect('/');
    }

    public function logout(Request $request)
    {
        $idToken = session('id_token');

        // Laravel user logged out
        Auth::logout();
        // destroy session
        $request->session()->invalidate();
        // prevent CSRF reuse
        $request->session()->regenerateToken();

        return redirect()->away(
            $this->oauthUrl('/connect/logout') . '?' . http_build_query([
                'id_token_hint' => $idToken,
                'post_logout_redirect_uri' => 'https://laravel-demo.test'
            ])
        );
    }
}
