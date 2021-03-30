PyPardot4
=========

PyPardot is an API wrapper for [Pardot](http://developer.pardot.com/kb/api-version-4/), written in Python.

Features
---

+ Includes all documented Pardot API operations
+ Handles API key expiration
+ Detailed API error handling

Object Types & Operations
---

Support for the following object types:

+ Accounts
+ Campaigns
+ Custom Fields
+ Custom Redirects
+ Dynamic Content
+ Emails
+ Email Clicks
+ Email Templates
+ Forms
+ Lifecycle Histories
+ Lifecycle Stages
+ Lists
+ List Memberships
+ Opportunities
+ Prospects
+ Prospect Accounts
+ Tags
+ TagObjects
+ Users
+ Visitor Activities
+ Visitors
+ Visits

Required
---

+ [requests](http://docs.python-requests.org/en/latest/)
+ [pyjwt](https://pyjwt.readthedocs.io/en/stable/)
+ [cryptography](https://cryptography.io/en/latest/)

Installation
---

Install PyPardot by running:
```shell
pip install pypardot4
```

Usage
---

### Authentication

To connect to the Pardot API you must setup a Salesforce SSO user that is able to acquire Pardot access tokens. See these articles for more information about Salesforce OAuth and how to set it up:

* https://developer.pardot.com/kb/authentication/
* https://help.salesforce.com/articleView?id=sf.remoteaccess_oauth_flows.htm&type=5
* https://help.salesforce.com/articleView?id=sf.remoteaccess_oauth_jwt_flow.htm&type=5

Specifically this version of PyPardot4 uses the OAuth2 JSON Web Token (JWT) Bearer Flow, which requires you to create a X509 Certificate and add it to the connected app configuration in Salesforce. PyPardot4 generates a JWT, which is signed with the certificate's private key, and is used by Salesforce to verify the signature and issue a Pardot API access token.

```python
api = PardotAPI(
    email='email@email.com',
    consumer_key='consumer_key',
    business_unit_id='business_unit_id',
    private_key_file='/path/to/private.key'
)
api.authenticate()

# or create from environment variables:
#   SFDC_EMAIL='email@email.com'
#   CONSUMER_KEY='consumer_key'
#   BUSINESS_UNIT_ID='business_unit_id'
#   PRIVATE_KEY_FILE='/path/to/private.key'

load_dotenv()
api = PardotAPI.from_env()
api.authenticate()
```

### Querying Objects

Supported search criteria varies for each object. Check the [official Pardot API documentation](http://developer.pardot.com/) for supported parameters. Most objects support `limit`, `offset`, `sort_by`, and `sort_order` parameters. PyPardot returns JSON for all API queries.

**Note**: Pardot only returns 200 records with each request. Use `offset` to retrieve matching records beyond this limit.

```python
# Query and iterate through today's prospects
prospects = p.prospects.query(created_after='yesterday')
total = prospects['total_results'] # total number of matching records
for prospect in prospects['prospect']
  print(prospect.get('first_name'))
```

### Editing/Updating/Reading Objects

Supported fields varies for each object. Check the [official Pardot API documentation](http://developer.pardot.com/kb/object-field-references/) to see the fields associated with each object. 

```python
# Create a new prospect
p.prospects.create_by_email(email='joe@company.com', first_name='Joe', last_name='Schmoe')

# Update a prospect field (works with default or custom field)
p.prospects.update_field_by_id(id=23839663, field_name='company', field_value='Joes Plumbing')

# Send a one-off email
p.emails.send_to_email(prospect_email='joe@company.com', email_template_id=123)
```

### Error Handling

#### Handling expired Salesforce access tokens

If the Pardot API responds with [error code 184](https://developer.pardot.com/kb/error-codes-messages/#error-code-184) then the access token sent with the request is invalid, unknown, or malformed. In this case, PyPardot4 makes the assumption that the access token has expired and refreshes the token before retrying the request once more. If the subsequent response also contains an error code then it is raised and the request will not be tried again.

#### Invalid API parameters

If an API call is made with missing or invalid parameters, a `PardotAPIError` is thrown. Error instances contain the error code and message corresponding to error response returned by the API. See [Pardot Error Codes & Messages](http://developer.pardot.com/kb/error-codes-messages/) in the official documentation.

Performing API calls is inherently unsafe, so be sure to catch exceptions:

```python
try:
  p.prospects.create_by_email(email='existing.email.address@company.com')
except PardotAPIError, e:
  print(e)
```
