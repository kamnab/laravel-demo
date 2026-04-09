# iframe interaction, required to send cookies from the logout application


SESSION_SAME_SITE=none
SESSION_SECURE_COOKIE=true

1. Add -> routes/web.php
```
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
```

2. Optional: Allow iframe header
```
use Illuminate\Support\Facades\Response;

public function boot()
{
    Response::macro('iframe', function ($content) {
        return response($content)
            ->header('X-Frame-Options', 'ALLOWALL')
            ->header('Content-Security-Policy', "frame-ancestors *");
    });
}
```