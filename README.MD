# OAuth2 Authorization Server for ProgrammerQ

### Interesting things about this repo

#### Implements its own OAuth2 Authorization Server

#### Leverages Auth0 OIDC on top of our OAuth2 Authorization Server

## Endpoints:

- `/login` : this will be used to authenticate the user. Provides the option of authentication to use
  - Currently only OAuth OIDC is used. So it redirects to `/oidc-auth0`
- `/oidc-auth0`: sets current session state to a value
- `/oidc-auth0/callback`: endpoint called post Auth0 authN. It checks that the state param in the request matches the
current user session state. Then, gets code from Auth0 and exchanges for a token, then gets tokenID and access token.
Then redirects to user
- `/user` : after Auth0 OIDC authentication callback occurs, it goes back to this endpoint. Here current user 
session is displayed. Then we redirect to consent on the claims
- `/consent` : from user session window, we move to this endpoint. Here scope grants will be asked in GUI for `grant` or 
`deny`
- `/authorize` : checks whether the user has been authenticated (redirects to app callback) or not (redirects to /login) 
- `token` : handles client request to obtain access tokens to protected resources

## TODO:

- Check code TODOs in code

- Add a `/consent` deny error page

- Switch from Cookie Session to server in-memory (only me as user...)

- Implement own OIDC Server

