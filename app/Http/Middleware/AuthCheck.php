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