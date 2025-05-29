import requests
import json
import uuid
import os
import secrets
import string
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple

# Load environment variables from .env file following Azure best practices
try:
    from dotenv import load_dotenv
    load_dotenv()
    logger = logging.getLogger(__name__)
    logger.info("Environment variables loaded from .env file")
except ImportError:
    print("⚠️  python-dotenv not found. Install with: pip install python-dotenv")
    print("   Or manually set environment variables in your shell")

# Configure logging for Azure best practices
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('entra_user_creation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AzureConfig:
    """
    Azure configuration management following Azure B2B best practices
    """
    def __init__(self):
        # Load from environment variables with validation
        self.tenant_id = os.getenv('AZURE_TENANT_ID')
        self.client_id = os.getenv('AZURE_CLIENT_ID')
        self.client_secret = os.getenv('AZURE_CLIENT_SECRET')
        
        # Validate required configuration
        missing_vars = []
        if not self.tenant_id:
            missing_vars.append('AZURE_TENANT_ID')
        if not self.client_id:
            missing_vars.append('AZURE_CLIENT_ID')
        if not self.client_secret:
            missing_vars.append('AZURE_CLIENT_SECRET')
            
        if missing_vars:
            error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
            logger.error(error_msg)
            logger.error("Please check your .env file or set these environment variables:")
            for var in missing_vars:
                logger.error(f"  export {var}='your-value-here'")
            raise ValueError(f"Azure credentials not properly configured: {', '.join(missing_vars)}")
        
        # Validate GUID format for tenant_id
        try:
            uuid.UUID(self.tenant_id)
        except ValueError:
            logger.error(f"Invalid tenant ID format: {self.tenant_id}")
            raise ValueError("AZURE_TENANT_ID must be a valid GUID")
        
        # Validate client_id GUID format
        try:
            uuid.UUID(self.client_id)
        except ValueError:
            logger.error(f"Invalid client ID format: {self.client_id}")
            raise ValueError("AZURE_CLIENT_ID must be a valid GUID")
        
        logger.info(f"✅ Azure B2B configuration loaded successfully for tenant: {self.tenant_id[:8]}...")

class SecurePasswordGenerator:
    """
    Secure password generator following EntraID password complexity requirements.
    """
    
    @staticmethod
    def generate_password(length: int = 16) -> str:
        """Generate a cryptographically secure password that meets EntraID requirements."""
        if length < 12:
            length = 12
            
        # Define character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        # EntraID safe special characters
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

class EntraB2BUserCreator:
    """
    Enhanced Entra ID user creator with B2B external user support following Azure best practices
    """
    def __init__(self, config: AzureConfig):
        self.config = config
        self.access_token = None
        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
        self.password_generator = SecurePasswordGenerator()
        self.verified_domains = None
    
    def get_access_token(self) -> Dict[str, Any]:
        """Get access token using client credentials flow following Azure best practices."""
        token_url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        
        token_data = {
            'client_id': self.config.client_id,
            'scope': 'https://graph.microsoft.com/.default',
            'client_secret': self.config.client_secret,
            'grant_type': 'client_credentials'
        }
        
        try:
            logger.info(f"🔑 Requesting access token for tenant: {self.config.tenant_id[:8]}...")
            response = requests.post(token_url, data=token_data, timeout=30)
            response.raise_for_status()
            
            token_response = response.json()
            self.access_token = token_response.get('access_token')
            
            if self.access_token:
                logger.info("✅ Access token acquired successfully")
                return {
                    "success": True,
                    "message": "Authentication successful",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "token_type": token_response.get('token_type', 'Bearer'),
                    "expires_in": token_response.get('expires_in', 3600)
                }
            else:
                logger.error("❌ Failed to acquire access token - no token in response")
                return {
                    "success": False,
                    "message": "Failed to acquire access token",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Error acquiring access token: {e}")
            return {
                "success": False,
                "message": f"Authentication error: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def get_verified_domains(self) -> List[str]:
        """
        Get verified domains for the tenant following Azure best practices.
        
        Returns:
            List of verified domain names
        """
        if self.verified_domains is not None:
            return self.verified_domains
            
        if not self.access_token:
            logger.error("No access token available for domain verification")
            return []
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            domains_url = f"{self.graph_endpoint}/domains"
            response = requests.get(domains_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            domains_data = response.json()
            verified_domains = []
            
            for domain in domains_data.get('value', []):
                if domain.get('isVerified', False):
                    verified_domains.append(domain.get('id'))
            
            self.verified_domains = verified_domains
            logger.info(f"🌐 Found {len(verified_domains)} verified domains: {', '.join(verified_domains)}")
            return verified_domains
            
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Error retrieving verified domains: {e}")
            # Fallback to common default domain pattern
            default_domain = f"telescopedevexternal.onmicrosoft.com"
            self.verified_domains = [default_domain]
            logger.warning(f"⚠️  Using fallback domain: {default_domain}")
            return self.verified_domains
    
    def create_external_user_upn(self, external_email: str, verified_domains: List[str]) -> str:
        """
        Create a valid UPN for external users following Azure B2B best practices.
        
        Azure B2B Pattern: externaluser_domain.com#EXT#@yourtenant.onmicrosoft.com
        
        Args:
            external_email: The user's external email address
            verified_domains: List of verified domains for the tenant
            
        Returns:
            Valid UPN for external user
        """
        # Use the primary verified domain (usually .onmicrosoft.com)
        primary_domain = None
        for domain in verified_domains:
            if domain.endswith('.onmicrosoft.com'):
                primary_domain = domain
                break
        
        if not primary_domain:
            primary_domain = verified_domains[0] if verified_domains else "telescopedevexternal.onmicrosoft.com"
        
        # Convert external email to B2B format
        # Replace @ with _ and add domain extension
        email_parts = external_email.split('@')
        if len(email_parts) != 2:
            raise ValueError(f"Invalid email format: {external_email}")
        
        username = email_parts[0]
        domain = email_parts[1]
        
        # Azure B2B UPN format: username_domain.com#EXT#@tenant.onmicrosoft.com
        b2b_upn = f"{username}_{domain}#EXT#@{primary_domain}"
        
        logger.info(f"🔗 Created B2B UPN: {external_email} -> {b2b_upn}")
        return b2b_upn
    
    def create_external_user(self, user_data: Dict[str, Any], return_password: bool = False) -> Dict[str, Any]:
        """
        Create an external user following Azure B2B best practices.
        
        Args:
            user_data: Dictionary containing user information with external email
            return_password: Whether to include the generated password in the response
            
        Returns:
            Dict containing creation result with user information or error details
        """
        if not self.access_token:
            return {
                "success": False,
                "message": "No access token available. Authentication required.",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        # Get verified domains
        verified_domains = self.get_verified_domains()
        if not verified_domains:
            return {
                "success": False,
                "message": "No verified domains found for tenant",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        # Extract external email from multiple possible field names
        external_email = (
            user_data.get('externalEmail') or 
            user_data.get('emailaddress') or 
            user_data.get('email') or 
            user_data.get('mail')
        )
        
        if not external_email:
            return {
                "success": False,
                "message": "External email is required for B2B user creation. Provide 'emailaddress', 'externalEmail', 'email', or 'mail' field.",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        try:
            # Create B2B UPN
            b2b_upn = self.create_external_user_upn(external_email, verified_domains)
            
            # Prepare user data for EntraID following B2B best practices
            azure_user_data = {
                "accountEnabled": user_data.get('accountEnabled', True),
                "displayName": user_data['displayName'],
                "userPrincipalName": b2b_upn,
                "mailNickname": user_data.get('mailNickname', external_email.split('@')[0]),
                "mail": external_email,  # Store original external email
                "givenName": user_data['givenName'],
                "surname": user_data['surname'],
                "userType": "Guest",  # Mark as external/guest user
                "otherMails": [external_email]  # Additional email addresses
            }
            
            # Add password profile if creating with password
            if 'passwordProfile' in user_data:
                azure_user_data['passwordProfile'] = user_data['passwordProfile']
            
            # Add optional fields
            optional_fields = ['jobTitle', 'department', 'officeLocation', 'mobilePhone', 'businessPhones']
            for field in optional_fields:
                if field in user_data:
                    azure_user_data[field] = user_data[field]
            
            # Add custom attributes if present
            if 'onPremisesExtensionAttributes' in user_data:
                azure_user_data['onPremisesExtensionAttributes'] = user_data['onPremisesExtensionAttributes']
            
            # Create the user
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            create_user_url = f"{self.graph_endpoint}/users"
            generated_password = None
            
            if 'passwordProfile' in azure_user_data:
                generated_password = azure_user_data['passwordProfile'].get('password')
            
            logger.info(f"👤 Creating external user: {user_data.get('displayName')} ({external_email})")
            response = requests.post(create_user_url, headers=headers, json=azure_user_data, timeout=30)
            response.raise_for_status()
            
            created_user = response.json()
            
            # Build successful response
            result = {
                "success": True,
                "message": "External user created successfully",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user": {
                    "objectId": created_user.get('id'),
                    "userPrincipalName": created_user.get('userPrincipalName'),
                    "displayName": created_user.get('displayName'),
                    "mail": created_user.get('mail'),
                    "externalEmail": external_email,
                    "userType": created_user.get('userType'),
                    "accountEnabled": created_user.get('accountEnabled'),
                    "createdDateTime": created_user.get('createdDateTime'),
                    "givenName": created_user.get('givenName'),
                    "surname": created_user.get('surname'),
                    "jobTitle": created_user.get('jobTitle'),
                    "department": created_user.get('department')
                }
            }
            
            # Add extension attributes if present
            if 'onPremisesExtensionAttributes' in created_user and created_user['onPremisesExtensionAttributes']:
                result["user"]["customAttributes"] = created_user['onPremisesExtensionAttributes']
            
            # Securely include password if requested
            if return_password and generated_password:
                result["credentials"] = {
                    "password": generated_password,
                    "forceChangePasswordNextSignIn": azure_user_data.get('passwordProfile', {}).get('forceChangePasswordNextSignIn', True),
                    "warning": "Store this password securely - it won't be available again"
                }
            
            logger.info(f"✅ External user created successfully: {external_email} -> {b2b_upn}")
            return result
            
        except requests.exceptions.HTTPError as e:
            error_detail = "Unknown error"
            try:
                error_response = response.json()
                error_detail = error_response.get('error', {}).get('message', str(e))
            except:
                error_detail = str(e)
            
            logger.error(f"❌ Error creating external user: {error_detail}")
            return {
                "success": False,
                "message": f"External user creation failed: {error_detail}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": {
                    "type": "HTTP_ERROR",
                    "details": error_detail,
                    "statusCode": getattr(response, 'status_code', None)
                }
            }
        except Exception as e:
            logger.error(f"❌ Error creating external user: {e}")
            return {
                "success": False,
                "message": f"Error: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": {
                    "type": "PROCESSING_ERROR",
                    "details": str(e)
                }
            }

def load_user_data(json_file_path: str = "users.json") -> Optional[Dict[str, Any]]:
    """Load user data from JSON file following Azure best practices."""
    try:
        if not os.path.exists(json_file_path):
            logger.error(f"JSON file not found: {json_file_path}")
            return None
        
        with open(json_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        if 'users' not in data or 'tenant_config' not in data:
            logger.error("Invalid JSON structure. Missing 'users' or 'tenant_config' sections.")
            return None
        
        logger.info(f"📋 Loaded {len(data['users'])} users from {json_file_path}")
        return data
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON format: {e}")
        return None
    except Exception as e:
        logger.error(f"Error loading JSON file: {e}")
        return None

def transform_external_user_data(user_info: Dict[str, Any], tenant_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform user info for external user creation following Azure B2B best practices.
    
    Args:
        user_info: User information from JSON
        tenant_config: Tenant configuration from JSON
        
    Returns:
        Dictionary formatted for EntraID external user creation
    """
    # Generate secure password if not specified
    password_generator = SecurePasswordGenerator()
    
    if 'password' in user_info and user_info['password']:
        password = user_info['password']
    else:
        password_length = tenant_config.get('password_length', 16)
        password = password_generator.generate_password(password_length)
        logger.info(f"🔐 Generated secure password for {user_info['displayName']}")
    
    # For external users, use their actual external email
    # Support multiple field names for flexibility
    external_email = (
        user_info.get('externalEmail') or 
        user_info.get('emailaddress') or 
        user_info.get('email') or 
        user_info.get('mail') or
        user_info.get('userPrincipalName')
    )
    
    if not external_email:
        raise ValueError(f"External email is required for user {user_info.get('displayName', 'Unknown')}. Provide 'emailaddress', 'externalEmail', 'email', or 'mail' field.")
    
    user_data = {
        "accountEnabled": user_info.get('accountEnabled', True),
        "displayName": user_info['displayName'],
        "externalEmail": external_email,
        "emailaddress": external_email,  # Support both naming conventions
        "mailNickname": user_info.get('mailNickname', external_email.split('@')[0]),
        "passwordProfile": {
            "forceChangePasswordNextSignIn": tenant_config.get('force_password_change', True),
            "password": password
        },
        "givenName": user_info['givenName'],
        "surname": user_info['surname']
    }
    
    # Add optional fields
    optional_fields = ['jobTitle', 'department', 'officeLocation', 'mobilePhone', 'businessPhones']
    for field in optional_fields:
        if field in user_info:
            user_data[field] = user_info[field]
    
    # Add custom primary_tenant_id attribute if provided
    if 'primary_tenant_id' in user_info:
        primary_tenant_id = user_info['primary_tenant_id']
        try:
            uuid.UUID(primary_tenant_id)
            user_data["onPremisesExtensionAttributes"] = {
                "extensionAttribute1": primary_tenant_id
            }
            logger.info(f"🏷️  Added primary_tenant_id: {primary_tenant_id[:8]}... for {user_info['displayName']}")
        except ValueError:
            logger.warning(f"⚠️  Invalid GUID format for primary_tenant_id: {primary_tenant_id} for user {user_info['displayName']}")
    
    return user_data

def create_external_users_from_json(json_file_path: str = "users.json", return_passwords: bool = False, 
                                   output_file: str = None) -> Dict[str, Any]:
    """
    Create external users in EntraID from JSON file following Azure B2B best practices.
    
    Args:
        json_file_path: Path to the JSON file containing user data
        return_passwords: Whether to include generated passwords in the response
        output_file: Optional path to save JSON output to file
        
    Returns:
        Dictionary containing complete operation results in JSON format
    """
    operation_start = datetime.now(timezone.utc)
    
    # Load user data from JSON
    data = load_user_data(json_file_path)
    if not data:
        return {
            "operation": {
                "success": False,
                "message": "Failed to load user data",
                "timestamp": operation_start.isoformat(),
                "duration": "0.00s"
            }
        }
    
    try:
        # Initialize Azure configuration
        config = AzureConfig()
        user_creator = EntraB2BUserCreator(config)
    except ValueError as e:
        return {
            "operation": {
                "success": False,
                "message": str(e),
                "timestamp": operation_start.isoformat(),
                "duration": f"{(datetime.now(timezone.utc) - operation_start).total_seconds():.2f}s"
            }
        }
    
    # Get access token
    auth_result = user_creator.get_access_token()
    if not auth_result["success"]:
        return {
            "operation": {
                "success": False,
                "message": "Authentication failed",
                "timestamp": operation_start.isoformat(),
                "duration": f"{(datetime.now(timezone.utc) - operation_start).total_seconds():.2f}s"
            },
            "authentication": auth_result
        }
    
    tenant_config = data['tenant_config']
    users_data = data['users']
    
    # Create users and collect results
    created_users = []
    failed_users = []
    
    for user_info in users_data:
        try:
            logger.info(f"👤 Processing external user: {user_info['displayName']}")
            
            # Transform user data for EntraID B2B
            user_data = transform_external_user_data(user_info, tenant_config)
            
            # Create the external user
            creation_result = user_creator.create_external_user(user_data, return_password=return_passwords)
            
            if creation_result["success"]:
                created_users.append(creation_result)
                logger.info(f"✅ Successfully created: {user_info['displayName']}")
            else:
                failed_users.append({
                    "displayName": user_info.get('displayName', 'Unknown'),
                    "externalEmail": user_info.get('emailaddress', user_info.get('email', 'Unknown')),
                    "error": creation_result
                })
                logger.error(f"❌ Failed to create: {user_info['displayName']}")
                
        except Exception as e:
            error_result = {
                "success": False,
                "message": f"Error processing user: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": {
                    "type": "PROCESSING_ERROR",
                    "details": str(e)
                }
            }
            failed_users.append({
                "displayName": user_info.get('displayName', 'Unknown'),
                "externalEmail": user_info.get('emailaddress', user_info.get('email', 'Unknown')),
                "error": error_result
            })
            logger.error(f"❌ Error processing: {user_info.get('displayName', 'Unknown')} - {str(e)}")
    
    operation_end = datetime.now(timezone.utc)
    duration = (operation_end - operation_start).total_seconds()
    
    # Build comprehensive result following Azure best practices
    result = {
        "operation": {
            "success": len(failed_users) == 0,
            "message": f"Processed {len(users_data)} external users using Azure B2B",
            "timestamp": operation_start.isoformat(),
            "duration": f"{duration:.2f}s"
        },
        "authentication": auth_result,
        "summary": {
            "total_users": len(users_data),
            "successful_creations": len(created_users),
            "failed_creations": len(failed_users),
            "success_rate": f"{(len(created_users) / len(users_data) * 100):.1f}%" if users_data else "0%"
        },
        "created_users": created_users,
        "failed_users": failed_users,
        "azure_b2b_info": {
            "pattern": "External users created with B2B UPN format: user_domain.com#EXT#@tenant.onmicrosoft.com",
            "user_type": "Guest",
            "original_emails_preserved": True,
            "supported_email_fields": ["emailaddress", "externalEmail", "email", "mail"]
        },
        "security_notes": {
            "passwords_included": return_passwords,
            "extension_attributes_used": "extensionAttribute1 for primary_tenant_id",
            "warning": "Handle generated passwords securely" if return_passwords else None
        }
    }
    
    # Save to file if requested
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            logger.info(f"💾 Results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save results to file: {e}")
    
    return result

if __name__ == "__main__":
    logger.info("🚀 Starting Azure Entra ID External User Creator (B2B)")
    
    # Check environment variables
    print("🔍 Validating Azure B2B configuration...")
    
    env_file_path = os.path.join(os.getcwd(), '.env')
    if os.path.exists(env_file_path):
        print(f"✅ Found .env file at: {env_file_path}")
    else:
        print("⚠️  No .env file found. Using system environment variables.")
    
    tenant_id = os.getenv('AZURE_TENANT_ID')
    client_id = os.getenv('AZURE_CLIENT_ID')
    client_secret = os.getenv('AZURE_CLIENT_SECRET')
    
    print(f"AZURE_TENANT_ID: {'✅ Set' if tenant_id else '❌ Not set'}")
    print(f"AZURE_CLIENT_ID: {'✅ Set' if client_id else '❌ Not set'}")
    print(f"AZURE_CLIENT_SECRET: {'✅ Set' if client_secret else '❌ Not set'}")
    
    if tenant_id:
        print(f"Tenant ID: {tenant_id[:8]}...{tenant_id[-4:]}")
    if client_id:
        print(f"Client ID: {client_id[:8]}...{client_id[-4:]}")
    
    print("\n🌐 Azure B2B External User Creation")
    print("   ✓ External users will be created with B2B UPN format")
    print("   ✓ Original email addresses will be preserved in 'mail' and 'otherMails'")
    print("   ✓ Supports 'emailaddress', 'externalEmail', 'email', and 'mail' fields")
    print("   ✓ Custom attributes stored in extension attributes")
    print()
    
    # Proceed with external user creation
    try:
        logger.info("📂 Loading user data and creating external users...")
        results = create_external_users_from_json("users.json", return_passwords=True, output_file="external_user_creation_results.json")
        
        # Print summary first
        if results["summary"]["successful_creations"] > 0:
            print(f"🎉 Successfully created {results['summary']['successful_creations']} out of {results['summary']['total_users']} users")
        
        if results["summary"]["failed_creations"] > 0:
            print(f"⚠️  Failed to create {results['summary']['failed_creations']} users")
        
        # Print JSON results to console
        print("\n📄 Detailed Operation Results:")
        print(json.dumps(results, indent=2, ensure_ascii=False))
        
    except Exception as e:
        logger.error(f"❌ Application error: {e}")
        error_result = {
            "operation": {
                "success": False,
                "message": f"Application error: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
        print(json.dumps(error_result, indent=2, ensure_ascii=False))