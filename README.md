# uaa-oauth2
Minimal User Account and Authentication.

## Support

### Grant type
- Authorization code grant
- Implicit grant
- ...

## OAuth2 Endpoints
- `/uaa/oauth/token`
- `/uaa/oauth/authorize`
- `/uaa/check_token`
- `/uaa/token_key`
- `/uaa/userinfo`

### Token Store
- In-memory

### Token format
- JWT(TODO)

### User account store
- RDBMS(H2)

### Does not support
- User account registration
