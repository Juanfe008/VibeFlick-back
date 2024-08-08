<?php

use App\Http\Controllers\Api\ApiController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('register', [ApiController::class, 'register']);
Route::post('login', [ApiController::class, 'login']);
Route::group(["middleware" => ['auth:sanctum']], function() {
    Route::get('user', [ApiController::class, 'user']);
    Route::get('logout', [ApiController::class, 'logout']);
});

/*Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');*/
