# uaa-oauth2
Minimal User Account and Authentication.

## Support

### Grant type
- Authorization code grant
- Implicit grant
- Resource owner password credentials grant

### User account store
- JDBC

### Client
- Single client and In-memory credentials(property file)

If multiple clients are needed, see below.
> [Adding more then one client to the Spring OAuth2 Auth Server](https://stackoverflow.com/a/35725709) 

## OAuth2 Endpoints
- `/uaa/oauth/token`
- `/uaa/oauth/authorize`
- `/uaa/check_token`
- `/uaa/token_key`
- `/uaa/userinfo`

### Approval store
- In-memory

### Token store
- In-memory

### Token format
- JWT(TODO)

## Does not support
- User account registration
