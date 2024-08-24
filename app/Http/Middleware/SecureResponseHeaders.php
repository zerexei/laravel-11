<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecureResponseHeaders
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (app()->isLocal()) return $next($request);

        // src: https://loadforge.com/guides/enhancing-laravel-security-a-guide-to-implementing-essential-http-headers
        $response = $next($request);

        // if (!$request->is('api/*')) {
        //     $response->headers->set('Access-Control-Allow-Origin', env('APP_URL')); // Replace example.com with your allowed origin
        //     $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        //     $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, X-Auth-Token, Origin');
        // }

        // Content Security Policy
        $cspValue = "frame-ancestors 'self' " . env('APP_URL');
        $response->headers->set('Content-Security-Policy', $cspValue);

        // X-Frame-Options
        $response->headers->set('X-Frame-Options', 'DENY');

        // X-XSS-Protection
        $response->headers->set('X-XSS-Protection', '1; mode=block');

        // X-Content-Type-Options
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Referrer Policy
        $response->headers->set('Referrer-Policy', 'no-referrer');

        // HTTP Strict Transport Security
        $response->headers->set('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');

        // Set Permissions-Policy header with necessary permissions only
        // src: https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/
        $permissionPolicy = "fullscreen=(self), geolocation=(self), microphone=(), camera=(),display-capture=(), document-domain=();";
        $response->headers->set('Permissions-Policy', $permissionPolicy);

        return $response;
    }
}
