# uaa-oauth2
Minimal User Account and Authentication.

## Support

### Grant type
- Authorization code grant
- Implicit grant
- Resource owner password credentials grant

## OAuth2 Endpoints
- `/uaa/oauth/token`
- `/uaa/oauth/authorize`
- `/uaa/check_token`
- `/uaa/token_key`
- `/uaa/userinfo`

### Token Store
- In-memory
- DB(TODO)

### Token format
- JWT(TODO)

### User account store
- DB

### Client
- Single client
- Multiple client(TODO)

### Does not support
- User account registration
