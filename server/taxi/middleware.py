from django.contrib.auth import get_user_model
from channels.auth import AuthMiddleware
from django.db import close_old_connections
from urllib.parse import parse_qs
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import AccessToken
from channels.sessions import CookieMiddleware, SessionMiddleware
from channels.db import database_sync_to_async


User = get_user_model()

@database_sync_to_async
def get_user(scope):
    close_old_connections()
    query_string = parse_qs(scope["query_string"].decode())
    token = query_string.get("token")
    if token is None:
        return AnonymousUser()
    try:
        access_token = AccessToken(token[0])
        user = User.objects.get(id=access_token["id"])
    except Exception:
        return AnonymousUser()
    if user.is_active is False:
        return AnonymousUser()
    return user


class TokenAuthMiddleware(AuthMiddleware):
    async def resolve_scope(self, scope):
        scope["user"]._wrapped = await get_user(scope)


def TokenAuthMiddlewareStack(inner):
    return CookieMiddleware(SessionMiddleware(TokenAuthMiddleware(inner)))
