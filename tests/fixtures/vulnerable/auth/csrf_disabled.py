# Intentionally vulnerable: CSRF protection disabled
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse


# VULNERABLE: CSRF check removed for this view
@csrf_exempt
def transfer_funds(request):
    amount = request.POST.get("amount")
    to_account = request.POST.get("to")
    return JsonResponse({"transferred": amount, "to": to_account})


# VULNERABLE: disabled globally in Flask-WTF
WTF_CSRF_ENABLED = False

# VULNERABLE: explicitly disabled
CSRF_ENABLED = False
