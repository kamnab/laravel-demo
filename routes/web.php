<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::get('/', function () {
    return view('welcome');
});


Route::get('/login', [AuthController::class, 'login'])->name('login');
Route::get('/callback/login/local', [AuthController::class, 'callback']);
Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
