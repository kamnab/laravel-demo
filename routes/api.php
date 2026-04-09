<?php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Illuminate\Support\Facades\Http;


Route::post('/backchannel-logout', function (Request $request) {
    $logoutToken = $request->input('logout_token');

    if (!$logoutToken) {
        return response()->json(['error' => 'missing token'], 400);
    }

    try {
        // ✅ 1. Load JWKS from Auth Server
        $response = Http::withoutVerifying()->get('https://localhost:44313/.well-known/jwks');
        if (!$response->ok()) {
            return response()->json([
                'error' => 'jwks_fetch_failed',
                'status' => $response->status(),
                'body' => $response->body()
            ], 500);
        }

        $jwks = $response->json();
        if (!$jwks || !isset($jwks['keys'])) {
            return response()->json([
                'error' => 'invalid_jwks_structure',
                'jwks' => $jwks
            ]);
        }

        // ✅ 2. Parse JWKS keys
        $keys = JWK::parseKeySet($jwks);

        // ✅ 3. Validate JWT signature + decode
        $parts = explode('.', $logoutToken);
        if (count($parts) !== 3) {
            return response()->json(['error' => 'invalid_jwt_format']);
        }

        $header = json_decode(base64_decode($parts[0]), true);
        if (!isset($header['kid']) || !isset($keys[$header['kid']])) {
            // fallback (single key case)
            $key = array_values($keys)[0];
            $decoded = JWT::decode($logoutToken, $key);
        } else {
            $decoded = JWT::decode($logoutToken, $keys);
        }
        /*
            {
                "aud":"php-demo-id",
                "iss":"https:\/\/localhost:44313",
                "exp":1775653062,
                "nbf":1775652762,
                "jti":"597a0200-377d-463d-8073-dbec113ef543",
                "iat":1775652762,
                "events":{"http:\/\/schemas.openid.net\/event\/backchannel-logout":{}},
                "sid":"2069f1bc-117e-40a0-9440-cdaa005d5bf5"
            }
        */

        // // -------------------------
        // // ✅ 4. Validate claims
        // // -------------------------

        // issuer
        if ($decoded->iss !== 'https://localhost:44313') {
            return response()->json(['error' => 'invalid issuer'], 400);
        }

        // audience (your client_id)
        if ($decoded->aud !== 'php-demo-id') {
            return response()->json(['error' => 'invalid audience'], 400);
        }

        // expiration
        if ($decoded->exp < time()) {
            return response()->json(['error' => 'token expired'], 400);
        }

        // ✅ Validate event
        $eventKey = 'http://schemas.openid.net/event/backchannel-logout';
        if (!isset($decoded->events) || !isset($decoded->events->$eventKey)) {
            return response()->json(['error' => 'invalid event'], 400);
        }

        // ✅ SID
        $sid = $decoded->sid ?? null;
        if (!$sid) {
            return response()->json(['error' => 'missing sid'], 400);
        }

        // -------------------------
        // ✅ 5. Prevent replay attack
        // -------------------------
        $jti = $decoded->jti ?? null;
        if ($jti) {
            if (Cache::has("logout_jti_$jti")) {
                return response()->json(['error' => 'replay detected'], 400);
            }

            Cache::put("logout_jti_$jti", true, $decoded->exp - time()); // Matches token lifetime
        }

        // ✅ Logout logic (proper way: lookup by SID)
        $userId = Cache::get("sid_$sid");
        if ($userId) {
            // Perform logout for this user, we dont know the user session, but we know the user ID from cache (stored during login), so we can log out by user ID.
            Auth::logout();
            session()->flush();
            Cache::forget("sid_$sid");

            return response()->json(['status' => 'ok', "sid_$sid" => $userId]);
        }

        /*/ -------------------------
        // ✅ 6. Match session
        // There is NO user session active when this endpoint is called, so we must rely on SID claim to identify which user to log out.
        // Backchannel logout is server-to-server call, so we can't rely on session cookie. 
        // Instead, we must match the SID claim with the one stored during login.
        ------------------------- /*/
        // $id_token = session('id_token');
        // $payload = explode('.', $id_token)[1];
        // $claims = json_decode(base64_decode($payload), true);
        // $sessionSid = $claims['sid'] ?? null;

        // if ($sid && $sessionSid === $sid) {
        // Auth::logout();
        // session()->flush();
        // }

        return response()->json(['status' => 'ok', "sid_$sid" => "no matching session found"]);
    } catch (\Exception $e) {
        return response()->json([
            'error' => 'invalid token',
            'message' => $e->getMessage()
        ], 400);
    }
});
