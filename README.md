## 1 Create new project
    - laravel new laravel-demo

## 2 AuthController.php
    - 📁 app/Http/Controllers/AuthController.php

## 3 Routes
    - routes/web.php

## 4 Protect routes (minimal auth check)
**📁 app/Http/Middleware/AuthCheck.php**

```
<?php

namespace App\Http\Middleware;

use Closure;

class AuthCheck
{
    public function handle($request, Closure $next)
    {
        if (!session()->has('access_token')) {
            return redirect('/login');
        }

        return $next($request);
    }
}
```

**📁 app/Http/Kernel.php**
```
protected $routeMiddleware = [
    'auth' => \App\Http\Middleware\AuthCheck::class,
];
```

## 5 Use Https
- composer global require laravel/valet
- valet install

## 6 Debug
- valet link laravel-demo
- valet secure laravel-demo

**Visit:**
    https://laravel-demo.test
