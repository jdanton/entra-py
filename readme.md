# Azure Entra ID User Creator

A Python utility for creating users in Azure Entra ID (formerly Azure Active Directory) with secure password generation and custom attribute support.

## Features

- 🔐 **Secure Password Generation**: Cryptographically secure passwords meeting EntraID requirements
- 👥 **Bulk User Creation**: Create multiple users from JSON configuration
- 🆔 **Custom Attributes**: Support for custom tenant ID attributes via extension attributes
- ✅ **Password Validation**: Built-in password strength validation
- 🔑 **EntraID Integration**: Uses Microsoft Graph API with OAuth 2.0 client credentials flow
- 📊 **Detailed Logging**: Comprehensive creation status and error reporting

## Prerequisites

- Python 3.7+
- EntraID tenant with administrative privileges
- App registration in EntraID with appropriate permissions

### Required EntraID Permissions

Your app registration needs the following Microsoft Graph permissions:
- `User.ReadWrite.All` (Application permission)
- `Directory.ReadWrite.All` (Application permission)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd entra-py
```

2. Install required dependencies:
```bash
pip install requests
```

## Configuration

### 1. Azure App Registration Setup

1. Go to Azure Portal > Azure Active Directory > App registrations
2. Create a new app registration
3. Generate a client secret
4. Grant the required API permissions
5. Admin consent for the permissions

### 2. Update Configuration

Edit the configuration values in [`entra-create-user.py`](entra-create-user.py):

```python
# Replace these with your actual values
TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-app-registration-client-id"
CLIENT_SECRET = "your-app-registration-secret"
```

### 3. Configure User Data

Edit [`users.json`](users.json) with your user information:

```json
{
  "tenant_config": {
    "domain": "yourdomain.onmicrosoft.com",
    "default_password": "TempPassword123!",
    "force_password_change": true,
    "password_length": 16
  },
  "users": [
    {
      "displayName": "John Doe",
      "mailNickname": "johndoe",
      "givenName": "John",
      "surname": "Doe",
      "jobTitle": "Software Developer",
      "department": "Engineering",
      "accountEnabled": true,
      "primary_tenant_id": "12345678-1234-1234-1234-123456789012"
    }
  ]
}
```

## Usage

### Bulk User Creation from JSON

```python
from entra_create_user import create_users_from_json

# Create users with secure password generation
created_users = create_users_from_json("users.json", return_passwords=True)
```

### Single User Creation

```python
from entra_create_user import create_single_user

user = create_single_user(
    display_name="Alice Johnson",
    email="alice.johnson@yourdomain.onmicrosoft.com",
    given_name="Alice",
    surname="Johnson",
    primary_tenant_id="11111111-2222-3333-4444-555555555555",
    return_password=True
)
```

### Running the Script

```bash
python entra-create-user.py
```

## Security Features

### Password Generation

The [`SecurePasswordGenerator`](entra-create-user.py) class provides:

- Cryptographically secure random password generation
- EntraID password complexity compliance
- Customizable password length (minimum 12 characters)
- Password strength validation

### Password Requirements

Generated passwords meet EntraID requirements:
- Minimum 8 characters (default: 16)
- Contains characters from at least 3 categories:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Numbers (0-9)
  - Special characters

## API Reference

### Classes

#### `EntraUserCreator`

Main class for creating users in EntraID.

**Methods:**
- `get_access_token()`: Acquire OAuth 2.0 access token
- `create_user(user_data, return_password=False)`: Create a single user

#### `SecurePasswordGenerator`

Utility class for secure password generation and validation.

**Methods:**
- `generate_password(length=16)`: Generate secure password
- `validate_password_strength(password)`: Validate password strength

### Functions

#### `create_users_from_json(json_file_path, return_passwords=False)`

Create multiple users from JSON configuration.

**Parameters:**
- `json_file_path`: Path to JSON file with user data
- `return_passwords`: Include generated passwords in response

**Returns:** List of created user information dictionaries

#### `create_single_user(display_name, email, given_name, surname, ...)`

Create a single user with custom details.

**Parameters:**
- `display_name`: Full display name
- `email`: User principal name (email)
- `given_name`: First name
- `surname`: Last name
- `primary_tenant_id`: Optional custom tenant ID (GUID)
- `password`: Optional custom password
- `return_password`: Include password in response

## File Structure

```
.
├── entra-create-user.py    # Main application code
├── users.json             # User configuration data
└── readme.md              # This documentation
```

## Custom Attributes

The utility supports adding custom attributes through EntraID extension attributes:

- `primary_tenant_id`: Stored in `extensionAttribute1`
- Automatically validates GUID format
- Gracefully handles invalid formats

## Error Handling

The application includes comprehensive error handling for:

- Authentication failures
- Invalid user data
- Network connectivity issues
- EntraID API errors
- JSON parsing errors
- Password validation failures

## Security Considerations

⚠️ **Important Security Notes:**

1. **Credential Management**: Never commit credentials to version control
2. **Password Handling**: Generated passwords are sensitive - handle securely
3. **Permissions**: Use least-privilege principle for app registrations
4. **Logging**: Avoid logging sensitive information in production
5. **Environment Variables**: Consider using environment variables for secrets

## Example Output

```
Azure External Tenant User Creator
========================================

✓ Access token acquired successfully

Processing user: John Doe
🔐 Generated secure password for John Doe
✓ User created successfully:
  Display Name: John Doe
  UPN: johndoe@yourdomain.onmicrosoft.com
  OID: 12345678-90ab-cdef-1234-567890abcdef
  Primary Tenant ID: 12345678-1234-1234-1234-123456789012
  🔐 Generated Password: SecureP@ssw0rd123!
     ⚠️  Store this password securely - it won't be shown again!

============================================================
CREATION SUMMARY
============================================================
✓ Successfully created: 1 users
✗ Failed to create: 0 users
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify tenant ID, client ID, and client secret
   - Ensure app registration has required permissions
   - Check if admin consent was granted

2. **User Creation Failures**
   - Verify user data format in JSON
   - Check for duplicate userPrincipalName
   - Ensure domain is correct

3. **Permission Errors**
   - Verify Graph API permissions
   - Ensure application permissions (not delegated)
   - Check admin consent status

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review EntraID documentation
3. Open an issue in the repository