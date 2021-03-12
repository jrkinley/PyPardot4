import jwt
import time
import requests
import logging
from requests.api import get, post
from .objects.accounts import Accounts
from .objects.customfields import CustomFields
from .objects.customredirects import CustomRedirects
from .objects.dynamiccontent import DynamicContent
from .objects.emailclicks import EmailClicks
from .objects.emailtemplates import EmailTemplates
from .objects.forms import Forms
from .objects.lifecyclehistories import LifecycleHistories
from .objects.lifecyclestages import LifecycleStages
from .objects.lists import Lists
from .objects.listmemberships import ListMemberships
from .objects.emails import Emails
from .objects.prospects import Prospects
from .objects.opportunities import Opportunities
from .objects.prospectaccounts import ProspectAccounts
from .objects.tags import Tags
from .objects.tagobjects import TagObjects
from .objects.users import Users
from .objects.visits import Visits
from .objects.visitors import Visitors
from .objects.visitoractivities import VisitorActivities
from .objects.campaigns import Campaigns

from .errors import PardotAPIError

logger = logging.getLogger(__name__)

# Issue #1 (http://code.google.com/p/pybing/issues/detail?id=1)
# Python 2.6 has json built in, 2.5 needs simplejson
try:
    import json
except ImportError:
    import simplejson as json

BASE_URI = 'https://pi.pardot.com'


class PardotAPI(object):
    def __init__(self, email, consumer_key, business_unit_id, 
                 private_key_file, salesforce_sandbox=False, version=4):
        self.email = email
        self.consumer_key = consumer_key
        self.business_unit_id = business_unit_id
        self.private_key_file = private_key_file
        self.salesforce_domain = 'https://{}.salesforce.com'.format('test' if salesforce_sandbox else 'login')
        self.version = version
        self.accounts = Accounts(self)
        self.campaigns = Campaigns(self)
        self.customfields = CustomFields(self)
        self.customredirects = CustomRedirects(self)
        self.dynamiccontent = DynamicContent(self)
        self.emailclicks = EmailClicks(self)
        self.emails = Emails(self)
        self.emailtemplates = EmailTemplates(self)
        self.forms = Forms(self)
        self.lifecyclehistories = LifecycleHistories(self)
        self.lifecyclestages = LifecycleStages(self)
        self.listmemberships = ListMemberships(self)
        self.lists = Lists(self)
        self.opportunities = Opportunities(self)
        self.prospects = Prospects(self)
        self.prospectaccounts = ProspectAccounts(self)
        self.tags = Tags(self)
        self.tagobjects = TagObjects(self)
        self.users = Users(self)
        self.visits = Visits(self)
        self.visitors = Visitors(self)
        self.visitoractivities = VisitorActivities(self)

    def post(self, object_name, path=None, params=None, retries=0):
        """Makes a POST request to the API."""
        return self._send('post', object_name, path, params, retries)

    def get(self, object_name, path=None, params=None, retries=0):
        """Makes a GET request to the API."""
        return self._send('get', object_name, path, params, retries)

    def _send(self, method, object_name, path=None, params=None, retries=0):
        """
        Sends request to the API. If the access token has expired then a new access token
        is acquired and the request is retried once. Returns the JSON response, or the HTTP
        status code if no JSON was returned.
        """
        if params is None:
            params = {}
        params.update({'format': 'json'})
        try:
            headers = self._build_auth_header()
            url = self._full_path(object_name, self.version, path)
            if method == 'post':
                request = requests.post(url, headers=headers, data=params)
            else:
                request = requests.get(url, headers=headers, params=params)
            response = self._check_response(request)
            return response
        except PardotAPIError as err:
            if err.err_code == 184:
                # Access token is invalid, unknown, or malformed.
                # Refresh token and retry once more
                if retries > 0:
                    raise err
                logger.warning(err.message)
                self.access_token = None
                self.authenticate()
                return self._send(method, object_name, path, params, retries=1)
            else:
                raise err

    @staticmethod
    def _full_path(object_name, version, path=None):
        """Builds the full path for the API request"""
        full = '{0}/api/{1}/version/{2}'.format(BASE_URI, object_name, version)
        if path:
            return '{0}{1}'.format(full, path)
        return full

    @staticmethod
    def _check_response(response):
        """
        Checks the HTTP response to see if it contains JSON. If it does, then checks the JSON for an error code
        and raises PardotAPIError if an error is found, else returns the JSON. If the response doesn't contain
        JSON then returns the HTTP response status code.
        """
        if response.headers.get('content-type') == 'application/json':
            json = response.json()
            error = json.get('err')
            if error:
                raise PardotAPIError(json_response=json)
            return json
        else:
            return response.status_code

    def authenticate(self):
        """
        Requests a Pardot API access token from Salesforce using the OAuth2 JWT Bearer Flow:
        https://help.salesforce.com/articleView?id=sf.remoteaccess_oauth_jwt_flow.htm&type=5
        """
        logger.info('Requesting Pardot API access token from Salesforce for: {}'.format(self.email))
        with open(self.private_key_file) as f:
            private_key = f.read()

        claim = {
            'iss': self.consumer_key,
            'exp': int(time.time()) + 300,
            'aud': self.salesforce_domain,
            'sub': self.email
        }

        assertion = jwt.encode(claim, private_key, algorithm='RS256').decode('utf8')
        response = requests.post(
            '{}/services/oauth2/token'.format(self.salesforce_domain),
            data = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': assertion
            }
        )
        logger.debug('Authentication response ({}): {}'.format(
            response.status_code, response.text))

        if response.status_code == 400:
            raise Exception('Authentication error: {}: {}'.format(
                response.json().get('error'),
                response.json().get('error_description')
            ))
        self.access_token = response.json().get('access_token')

    def _build_auth_header(self):
        """
        Builds Pardot authorization header
        """
        if self.access_token is None:
            self.authenticate()
        return {
            'Authorization': 'Bearer {}'.format(self.access_token),
            'Pardot-Business-Unit-Id': self.business_unit_id
        }
