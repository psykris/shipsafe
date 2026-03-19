# Intentionally vulnerable: overly permissive default permissions

# VULNERABLE: DRF default allows any unauthenticated user
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"]
}

# VULNERABLE: empty permission list (no access control)
from rest_framework.views import APIView


class PublicDataView(APIView):
    permission_classes = []

    def get(self, request):
        return {"data": "sensitive"}


# VULNERABLE: anonymous access explicitly enabled
allow_anonymous = True
