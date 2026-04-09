# Server to server interaction, no session no cookies

1. Add -> routes/api.php
composer require firebase/php-jwt

```
Route::post('/backchannel-logout', function (Request $request) {

}
```

2. Register at app/Providers/AppServiceProvider.php

```
    use Illuminate\Support\Facades\Route;
    public function boot(): void
    {
        Route::middleware('api')
            ->prefix('api')
            ->group(base_path('routes/api.php'));

        // Route::middleware('web')
        //     ->group(base_path('routes/web.php'));
    }
```

3. Check route 
- php artisan route:list | grep logout
