<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;
use App\Http\Controllers\AuthController;

Route::get('/', function () {
    return view('welcome');
});


Route::get('/login', [AuthController::class, 'login'])->name('login');
Route::get('/callback/login/local', [AuthController::class, 'callback']);
Route::post('/logout', [AuthController::class, 'logout'])->name('logout');

/*
 * Backchannel logout endpoint (called by OAUTH server)
 * - Validates logout token (JWT) sent by OAUTH server
 * - Invalidates user session based on SID claim
 * - Does NOT rely on browser cookies (can be called by OAUTH server directly)
 * - Prevents replay attack by storing JTI in cache
 * - Proper way: lookup user session by SID claim, but we don't have real user sessions in this demo, so we just demonstrate logout logic by user ID stored in cache during login.
 * - Note: In real implementation, you should also verify the client certificate of the OAUTH server to ensure the request is legitimate.
 * - For testing: you can use Postman to send a POST request to this endpoint with a valid logout token in the body, and observe the logout behavior.
 * - For frontchannel logout (optional): you can also implement a GET endpoint that accepts SID as query parameter, and logs out the user if the SID matches the current session. This can be used for frontchannel logout where the OAUTH server redirects the user's browser to this endpoint.
 * - For simplicity, this demo focuses on backchannel logout and does not implement client certificate verification or a real user session store. The key point is to demonstrate how to validate the logout token and perform logout based on SID claim.
 * - For more details on backchannel logout, you can refer to the OpenID Connect Back-Channel Logout specification: https://openid.net/specs/openid-connect-backchannel-1_0.html

.env settings:
SESSION_SAME_SITE=none          // This allows the session cookie to be sent in cross-origin requests, which is necessary for the backchannel logout to work when the OAUTH server is on a different domain.
SESSION_SECURE_COOKIE=true      // This ensures that the session cookie is only sent over HTTPS, which is important for security, especially when using cross-origin cookies.
*/
Route::get('/frontchannel-logout', function (Request $request) {

    $sid = $request->query('sid');

    if ($sid && session('sid') === $sid) {
        // ✅ Logout user session (browser session)
        Auth::logout();

        // ✅ Destroy session
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return response('OK', 200);
    }

    return response('NOT OK', 200);
});

Route::get('/users', function () {

    // 1️⃣ Get already-authenticated user's access token
    $accessToken = session('access_token');

    if (!$accessToken) {
        return response()->json([
            'error' => 'No access token found. User not authenticated with OAuth server.'
        ], 401);
    }

    // 2️⃣ Call ASP.NET API with token
    $response = Http::withoutVerifying()->withToken($accessToken)
        ->acceptJson()
        ->get('https://localhost:44313/api/v1/users/meta');

    // 3️⃣ Handle response
    if ($response->unauthorized()) {
        return response()->json(['error' => '401 Unauthorized'], 401);
    }

    if ($response->forbidden()) {
        return response()->json(['error' => '403 Forbidden (missing scope)'], 403);
    }

    return response()->json($response->json());
});