import requests
import json
import uuid
import os
import secrets
import string
from typing import Dict, Any, Optional, List, Tuple

class SecurePasswordGenerator:
    """
    Secure password generator following Azure AD password complexity requirements.
    """
    
    @staticmethod
    def generate_password(length: int = 16) -> str:
        """
        Generate a cryptographically secure password that meets Azure AD requirements.
        
        Azure AD Password Requirements:
        - At least 8 characters (we use 16 for better security)
        - Contains characters from at least 3 of these categories:
          * Uppercase letters (A-Z)
          * Lowercase letters (a-z) 
          * Numbers (0-9)
          * Special characters
        
        Args:
            length: Password length (minimum 12, default 16)
            
        Returns:
            Secure password string
        """
        if length < 12:
            length = 12
            
        # Define character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        # Azure AD safe special characters
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure we have at least one character from each category
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special_chars)
        ]
        
        # Fill the rest with random characters from all sets
        all_chars = uppercase + lowercase + digits + special_chars
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password list to randomize positions
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against Azure AD requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        if len(password) < 8:
            issues.append("Password must be at least 8 characters long")
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        categories = sum([has_upper, has_lower, has_digit, has_special])
        
        if categories < 3:
            issues.append("Password must contain characters from at least 3 categories (uppercase, lowercase, numbers, special characters)")
        
        # Check for common weak patterns
        if password.lower() in ['password', '12345678', 'qwerty123']:
            issues.append("Password is too common")
            
        return len(issues) == 0, issues

class EntraUserCreator:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        """
        Initialize the Entra ID user creator.
        
        Args:
            tenant_id: Your Azure AD tenant ID
            client_id: Application (client) ID from app registration
            client_secret: Client secret from app registration
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
        self.password_generator = SecurePasswordGenerator()
    
    def get_access_token(self) -> bool:
        """
        Get access token using client credentials flow.
        
        Returns:
            bool: True if token acquired successfully, False otherwise
        """
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        
        token_data = {
            'client_id': self.client_id,
            'scope': 'https://graph.microsoft.com/.default',
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        
        try:
            response = requests.post(token_url, data=token_data)
            response.raise_for_status()
            
            token_response = response.json()
            self.access_token = token_response.get('access_token')
            
            if self.access_token:
                print("✓ Access token acquired successfully")
                return True
            else:
                print("✗ Failed to acquire access token")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"✗ Error acquiring access token: {e}")
            return False
    
    def create_user(self, user_data: Dict[str, Any], return_password: bool = False) -> Optional[Dict[str, Any]]:
        """
        Create a new user in Azure AD.
        
        Args:
            user_data: Dictionary containing user information
            return_password: Whether to include the generated password in the response
            
        Returns:
            Dict containing created user information including OID, or None if failed
        """
        if not self.access_token:
            print("✗ No access token available. Call get_access_token() first.")
            return None
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        create_user_url = f"{self.graph_endpoint}/users"
        
        # Store the generated password if it was auto-generated
        generated_password = None
        if 'passwordProfile' in user_data and hasattr(user_data['passwordProfile'], 'get'):
            generated_password = user_data['passwordProfile'].get('password')
        
        try:
            response = requests.post(create_user_url, headers=headers, json=user_data)
            response.raise_for_status()
            
            created_user = response.json()
            
            # Extract key information including OID
            user_info = {
                'oid': created_user.get('id'),  # This is the Object ID (OID)
                'userPrincipalName': created_user.get('userPrincipalName'),
                'displayName': created_user.get('displayName'),
                'mail': created_user.get('mail'),
                'accountEnabled': created_user.get('accountEnabled'),
                'createdDateTime': created_user.get('createdDateTime'),
                'extensionAttributes': created_user.get('onPremisesExtensionAttributes', {}),
                'full_response': created_user  # Include full response if needed
            }
            
            # Securely include password if requested
            if return_password and generated_password:
                user_info['generated_password'] = generated_password
                print("⚠️  Generated password included in response - handle securely!")
            
            print(f"✓ User created successfully:")
            print(f"  Display Name: {user_info['displayName']}")
            print(f"  UPN: {user_info['userPrincipalName']}")
            print(f"  OID: {user_info['oid']}")
            
            # Display custom attribute if present
            if 'onPremisesExtensionAttributes' in created_user and created_user['onPremisesExtensionAttributes']:
                ext_attrs = created_user['onPremisesExtensionAttributes']
                if 'extensionAttribute1' in ext_attrs:
                    print(f"  Primary Tenant ID: {ext_attrs['extensionAttribute1']}")
            
            # Display password securely (only in development)
            if return_password and generated_password:
                print(f"  🔐 Generated Password: {generated_password}")
                print("     ⚠️  Store this password securely - it won't be shown again!")
            
            return user_info
            
        except requests.exceptions.HTTPError as e:
            error_detail = ""
            try:
                error_response = response.json()
                error_detail = error_response.get('error', {}).get('message', str(e))
            except:
                error_detail = str(e)
            
            print(f"✗ Error creating user: {error_detail}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"✗ Network error creating user: {e}")
            return None

def load_user_data(json_file_path: str = "sample_users.json") -> Optional[Dict[str, Any]]:
    """
    Load user data from JSON file.
    
    Args:
        json_file_path: Path to the JSON file containing user data
        
    Returns:
        Dictionary containing user data or None if failed
    """
    try:
        # Check if file exists
        if not os.path.exists(json_file_path):
            print(f"✗ JSON file not found: {json_file_path}")
            return None
        
        with open(json_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        # Validate required structure
        if 'users' not in data or 'tenant_config' not in data:
            print("✗ Invalid JSON structure. Missing 'users' or 'tenant_config' sections.")
            return None
        
        print(f"✓ Loaded {len(data['users'])} users from {json_file_path}")
        return data
        
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON format: {e}")
        return None
    except Exception as e:
        print(f"✗ Error loading JSON file: {e}")
        return None

def transform_user_data(user_info: Dict[str, Any], tenant_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform user info from JSON into Azure AD user creation format.
    
    Args:
        user_info: User information from JSON
        tenant_config: Tenant configuration from JSON
        
    Returns:
        Dictionary formatted for Azure AD user creation
    """
    # Generate secure password if not specified
    password_generator = SecurePasswordGenerator()
    
    if 'password' in user_info and user_info['password']:
        # Use provided password
        password = user_info['password']
        # Validate provided password
        is_valid, issues = password_generator.validate_password_strength(password)
        if not is_valid:
            print(f"⚠️  Warning: Provided password for {user_info['displayName']} may not meet Azure AD requirements:")
            for issue in issues:
                print(f"   - {issue}")
    else:
        # Generate secure password
        password_length = tenant_config.get('password_length', 16)
        password = password_generator.generate_password(password_length)
        print(f"🔐 Generated secure password for {user_info['displayName']}")
    
    # Build userPrincipalName
    domain = tenant_config.get('domain', 'yourdomain.onmicrosoft.com')
    upn = f"{user_info['mailNickname']}@{domain}"
    
    user_data = {
        "accountEnabled": user_info.get('accountEnabled', True),
        "displayName": user_info['displayName'],
        "mailNickname": user_info['mailNickname'],
        "userPrincipalName": upn,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": tenant_config.get('force_password_change', True),
            "password": password
        },
        "givenName": user_info['givenName'],
        "surname": user_info['surname']
    }
    
    # Add optional fields if present
    optional_fields = ['jobTitle', 'department', 'officeLocation', 'mobilePhone', 'businessPhones']
    for field in optional_fields:
        if field in user_info:
            user_data[field] = user_info[field]
    
    # Add custom primary_tenant_id attribute if provided
    if 'primary_tenant_id' in user_info:
        primary_tenant_id = user_info['primary_tenant_id']
        try:
            # Validate GUID format
            uuid.UUID(primary_tenant_id)
            user_data["onPremisesExtensionAttributes"] = {
                "extensionAttribute1": primary_tenant_id
            }
        except ValueError:
            print(f"Warning: Invalid GUID format for primary_tenant_id: {primary_tenant_id}")
            print(f"User {user_info['displayName']} will be created without the custom attribute.")
    
    return user_data

def create_users_from_json(json_file_path: str = "sample_users.json", return_passwords: bool = False) -> List[Dict[str, Any]]:
    """
    Create users in the external tenant from JSON file.
    
    Args:
        json_file_path: Path to the JSON file containing user data
        return_passwords: Whether to include generated passwords in the response
        
    Returns:
        List of created user information dictionaries
    """
    # Load user data from JSON
    data = load_user_data(json_file_path)
    if not data:
        return []
    
    # Configuration - Replace with your actual values
    TENANT_ID = "598c44cc-c795-4d3b-9b71-ad77e74e1bdb"
    CLIENT_ID = "your-app-registration-client-id"  # Replace with actual client ID
    CLIENT_SECRET = "your-app-registration-secret"  # Replace with actual secret
    
    # Initialize the user creator
    user_creator = EntraUserCreator(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    
    # Get access token
    if not user_creator.get_access_token():
        print("Failed to authenticate. Please check your credentials.")
        return []
    
    tenant_config = data['tenant_config']
    users_data = data['users']
    
    # Create users and collect results
    created_users = []
    failed_users = []
    
    for user_info in users_data:
        try:
            print(f"\nProcessing user: {user_info['displayName']}")
            
            # Transform user data for Azure AD
            user_data = transform_user_data(user_info, tenant_config)
            
            # Create the user
            created_user = user_creator.create_user(user_data, return_password=return_passwords)
            
            if created_user:
                created_users.append(created_user)
            else:
                failed_users.append(user_info['displayName'])
                
        except KeyError as e:
            print(f"✗ Missing required field for user {user_info.get('displayName', 'Unknown')}: {e}")
            failed_users.append(user_info.get('displayName', 'Unknown'))
        except Exception as e:
            print(f"✗ Error processing user {user_info.get('displayName', 'Unknown')}: {e}")
            failed_users.append(user_info.get('displayName', 'Unknown'))
    
    # Summary
    print(f"\n{'='*60}")
    print(f"CREATION SUMMARY")
    print(f"{'='*60}")
    print(f"✓ Successfully created: {len(created_users)} users")
    print(f"✗ Failed to create: {len(failed_users)} users")
    
    if created_users:
        print(f"\nCreated Users:")
        for user in created_users:
            print(f"  • {user['displayName']} (OID: {user['oid']})")
    
    if failed_users:
        print(f"\nFailed Users:")
        for user_name in failed_users:
            print(f"  • {user_name}")
    
    # Security reminder
    if return_passwords and created_users:
        print(f"\n🔐 SECURITY REMINDER:")
        print(f"   Generated passwords are included in the response.")
        print(f"   Ensure you handle them securely and store them appropriately.")
    
    return created_users

def create_single_user(display_name: str, email: str, given_name: str, surname: str, 
                      primary_tenant_id: str = None, password: str = None, 
                      return_password: bool = True) -> Optional[Dict[str, Any]]:
    """
    Create a single user with custom details and optional primary_tenant_id.
    
    Args:
        display_name: Full display name
        email: Email address (userPrincipalName)
        given_name: First name
        surname: Last name
        primary_tenant_id: Optional GUID for primary tenant ID
        password: Optional custom password (if None, a secure password will be generated)
        return_password: Whether to include the password in the response
        
    Returns:
        Dict containing user information including OID, or None if failed
    """
    # Configuration
    TENANT_ID = "598c44cc-c795-4d3b-9b71-ad77e74e1bdb"
    CLIENT_ID = "your-app-registration-client-id"  # Replace with actual client ID
    CLIENT_SECRET = "your-app-registration-secret"  # Replace with actual secret
    
    user_creator = EntraUserCreator(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    
    if not user_creator.get_access_token():
        print("Failed to authenticate.")
        return None
    
    # Generate secure password if not provided
    if not password:
        password_generator = SecurePasswordGenerator()
        password = password_generator.generate_password()
        print(f"🔐 Generated secure password for {display_name}")
    else:
        # Validate provided password
        password_generator = SecurePasswordGenerator()
        is_valid, issues = password_generator.validate_password_strength(password)
        if not is_valid:
            print(f"⚠️  Warning: Provided password may not meet Azure AD requirements:")
            for issue in issues:
                print(f"   - {issue}")
    
    user_data = {
        "accountEnabled": True,
        "displayName": display_name,
        "mailNickname": email.split('@')[0],
        "userPrincipalName": email,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": password
        },
        "givenName": given_name,
        "surname": surname
    }
    
    # Add custom attribute if provided
    if primary_tenant_id:
        # Validate GUID format
        try:
            uuid.UUID(primary_tenant_id)
            user_data["onPremisesExtensionAttributes"] = {
                "extensionAttribute1": primary_tenant_id
            }
            print(f"Adding primary_tenant_id: {primary_tenant_id}")
        except ValueError:
            print(f"Warning: Invalid GUID format for primary_tenant_id: {primary_tenant_id}")
            print("User will be created without the custom attribute.")
    
    return user_creator.create_user(user_data, return_password=return_password)

if __name__ == "__main__":
    print("Azure External Tenant User Creator")
    print("=" * 40)
    
    # Option 1: Create users from JSON file with secure password generation
    print("\n1. Creating users from JSON file with secure passwords...")
    users_with_oids = create_users_from_json("sample_users.json", return_passwords=True)
    
    # Option 2: Create a single custom user with generated password (uncomment to use)
    # print("\n2. Creating custom user with generated secure password...")
    # custom_user = create_single_user(
    #     display_name="Alice Johnson",
    #     email="alice.johnson@yourdomain.onmicrosoft.com",
    #     given_name="Alice",
    #     surname="Johnson",
    #     primary_tenant_id="11111111-2222-3333-4444-555555555555",
    #     return_password=True
    # )
    # if custom_user:
    #     print(f"Custom user created:")
    #     print(f"  Name: {custom_user['displayName']}")
    #     print(f"  UPN: {custom_user['userPrincipalName']}")
    #     print(f"  OID: {custom_user['oid']}")
    #     if 'generated_password' in custom_user:
    #         print(f"  Password: {custom_user['generated_password']}")