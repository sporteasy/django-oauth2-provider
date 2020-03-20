from base64 import b64decode

from django.utils.encoding import force_bytes

from ..utils import now
from .forms import ClientAuthForm, PublicPasswordGrantForm
from .models import AccessToken


class BaseBackend(object):
    """
    Base backend used to authenticate clients as defined in :rfc:`1` against
    our database.
    """
    def authenticate(self, request=None):
        """
        Override this method to implement your own authentication backend.
        Return a client or ``None`` in case of failure.
        """
        pass


class BasicClientBackend(object):
    """
    Backend that tries to authenticate a client through HTTP authorization
    headers as defined in :rfc:`2.3.1`.
    """
    def authenticate(self, request=None):
        auth = request.META.get('HTTP_AUTHORIZATION')

        if auth is None or auth == '':
            return None

        try:
            basic, base64 = auth.split(' ')
            client_id, client_secret = b64decode(force_bytes(base64)).decode("ascii").split(':')

            form = ClientAuthForm({
                'client_id': client_id,
                'client_secret': client_secret})

            if form.is_valid():
                return form.cleaned_data.get('client')
            return None

        except ValueError:
            # Auth header was malformed, unpacking went wrong
            return None


class RequestParamsClientBackend(object):
    """
    Backend that tries to authenticate a client through request parameters
    which might be in the request body or URI as defined in :rfc:`2.3.1`.
    """
    def authenticate(self, request=None):
        if request is None:
            return None

        data = {
            'client_id': request.POST.get('client_id', request.GET.get('client_id')),
            'client_secret': request.POST.get('client_secret', request.GET.get('client_secret'))
        }
        form = ClientAuthForm(data)

        if form.is_valid():
            return form.cleaned_data.get('client')

        return None


class PublicPasswordBackend(object):
    """
    Backend that tries to authenticate a client using username, password
    and client ID. This is only available in specific circumstances:

     - grant_type is "password"
     - client.client_type is 'public'
    """

    def authenticate(self, request=None):
        if request is None:
            return None

        data = {
            'client_id': request.POST.get('client_id', request.GET.get('client_id')),
            'username': request.POST.get('username', request.GET.get('username')),
            'password': request.POST.get('password', request.GET.get('password')),
            'scope': request.POST.get('scope', request.GET.get('scope')),
        }
        form = PublicPasswordGrantForm(data)

        if form.is_valid():
            return form.cleaned_data.get('client')

        return None


class AccessTokenBackend(object):
    """
    Authenticate a user via access token and client object.
    """

    def authenticate(self, access_token=None, client=None):
        try:
            return AccessToken.objects.get(token=access_token,
                expires__gt=now(), client=client)
        except AccessToken.DoesNotExist:
            return None
