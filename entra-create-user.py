import requests
import json
from typing import Dict, Any, Optional

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
    
    def create_user(self, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Create a new user in Azure AD.
        
        Args:
            user_data: Dictionary containing user information
            
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
            
            print(f"✓ User created successfully:")
            print(f"  Display Name: {user_info['displayName']}")
            print(f"  UPN: {user_info['userPrincipalName']}")
            print(f"  OID: {user_info['oid']}")
            
            # Display custom attribute if present
            if 'onPremisesExtensionAttributes' in created_user and created_user['onPremisesExtensionAttributes']:
                ext_attrs = created_user['onPremisesExtensionAttributes']
                if 'extensionAttribute1' in ext_attrs:
                    print(f"  Primary Tenant ID: {ext_attrs['extensionAttribute1']}")
            
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

def create_sample_users():
    """
    Create sample users in the external tenant with custom primary_tenant_id attribute.
    """
    # Configuration - Replace with your actual values
    TENANT_ID = "your-tenant-id"  # Replace with actual tenant ID
    CLIENT_ID = "your-app-registration-client-id"  # Replace with actual client ID
    CLIENT_SECRET = "your-app-registration-secret"  # Replace with actual secret
    
    # Initialize the user creator
    user_creator = EntraUserCreator(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    
    # Get access token
    if not user_creator.get_access_token():
        print("Failed to authenticate. Please check your credentials.")
        return []
    
    # Sample users to create with custom attribute
    sample_users = [
        {
            "accountEnabled": True,
            "displayName": "John Doe",
            "mailNickname": "johndoe",
            "userPrincipalName": "johndoe@yourdomain.onmicrosoft.com",  # Update domain
            "passwordProfile": {
                "forceChangePasswordNextSignIn": True,
                "password": "TempPassword123!"
            },
            "givenName": "John",
            "surname": "Doe",
            "jobTitle": "Software Developer",
            "department": "Engineering",
            # Custom attribute using extension attributes
            "onPremisesExtensionAttributes": {
                "extensionAttribute1": "12345678-1234-1234-1234-123456789012"  # primary_tenant_id GUID
            }
        },
        {
            "accountEnabled": True,
            "displayName": "Jane Smith",
            "mailNickname": "janesmith",
            "userPrincipalName": "janesmith@yourdomain.onmicrosoft.com",  # Update domain
            "passwordProfile": {
                "forceChangePasswordNextSignIn": True,
                "password": "TempPassword456!"
            },
            "givenName": "Jane",
            "surname": "Smith",
            "jobTitle": "Product Manager",
            "department": "Product",
            # Custom attribute using extension attributes
            "onPremisesExtensionAttributes": {
                "extensionAttribute1": "87654321-4321-4321-4321-210987654321"  # primary_tenant_id GUID
            }
        }
    ]
    
    # Create users and collect results
    created_users = []
    for user_data in sample_users:
        print(f"\nCreating user: {user_data['displayName']}")
        created_user = user_creator.create_user(user_data)
        
        if created_user:
            created_users.append(created_user)
        else:
            print(f"  Failed to create user: {user_data['displayName']}")
    
    # Summary with OIDs
    print(f"\n{'='*50}")
    print(f"Summary: {len(created_users)} out of {len(sample_users)} users created successfully")
    print("\nCreated Users with OIDs:")
    for user in created_users:
        print(f"  • {user['displayName']} (OID: {user['oid']})")
    
    return created_users

def create_single_user(display_name: str, email: str, given_name: str, surname: str, primary_tenant_id: str = None) -> Optional[Dict[str, Any]]:
    """
    Create a single user with custom details and optional primary_tenant_id.
    
    Args:
        display_name: Full display name
        email: Email address (userPrincipalName)
        given_name: First name
        surname: Last name
        primary_tenant_id: Optional GUID for primary tenant ID
        
    Returns:
        Dict containing user information including OID, or None if failed
    """
    import uuid
    
    # Configuration
    TENANT_ID = "598c44cc-c795-4d3b-9b71-ad77e74e1bdb"
    CLIENT_ID = "your-app-registration-client-id"  # Replace with actual client ID
    CLIENT_SECRET = "your-app-registration-secret"  # Replace with actual secret
    
    user_creator = EntraUserCreator(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    
    if not user_creator.get_access_token():
        print("Failed to authenticate.")
        return None
    
    user_data = {
        "accountEnabled": True,
        "displayName": display_name,
        "mailNickname": email.split('@')[0],
        "userPrincipalName": email,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": "TempPassword789!"
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
    
    return user_creator.create_user(user_data)

if __name__ == "__main__":
    print("Azure External Tenant User Creator")
    print("=" * 40)
    
    # Option 1: Create sample users with custom attributes
    print("\n1. Creating sample users...")
    users_with_oids = create_sample_users()
    
    # Example: Access OIDs from returned data
    if users_with_oids:
        print(f"\nExample - Accessing OIDs programmatically:")
        for user in users_with_oids:
            print(f"User: {user['displayName']}, OID: {user['oid']}")
    
    # Option 2: Create a single custom user with primary_tenant_id (uncomment to use)
    # print("\n2. Creating custom user with primary_tenant_id...")
    # custom_user = create_single_user(
    #     display_name="Alice Johnson",
    #     email="alice.johnson@yourdomain.onmicrosoft.com",
    #     given_name="Alice",
    #     surname="Johnson",
    #     primary_tenant_id="11111111-2222-3333-4444-555555555555"
    # )
    # if custom_user:
    #     print(f"Custom user created:")
    #     print(f"  Name: {custom_user['displayName']}")
    #     print(f"  UPN: {custom_user['userPrincipalName']}")
    #     print(f"  OID: {custom_user['oid']}")