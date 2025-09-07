from django.shortcuts import render
from django.http import JsonResponse
from ratelimit.decorators  import ratelimit # type: ignore
from django.contrib.auth import authenticate, login

# Limit login view
@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
def login_view(request):
    """
    Login view with rate limiting:
    - Authenticated users: 10 requests per minute
    - Anonymous users: 5 requests per minute
    """
    if request.method == "POST":
        # Check rate limit
        was_limited = getattr(request, 'limited', False)
        if was_limited:
            return JsonResponse({'error': 'Rate limit exceeded.'}, status=429)

        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({'success': 'Logged in'})
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=400)

    return render(request, "login.html")
