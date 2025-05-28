import requests
import json
import uuid
import os
import secrets
import string
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

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
    
    def get_access_token(self) -> Dict[str, Any]:
        """
        Get access token using client credentials flow.
        
        Returns:
            Dict with authentication result and status
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
                logger.info("Access token acquired successfully")
                return {
                    "success": True,
                    "message": "Authentication successful",
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                logger.error("Failed to acquire access token")
                return {
                    "success": False,
                    "message": "Failed to acquire access token",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error acquiring access token: {e}")
            return {
                "success": False,
                "message": f"Authentication error: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def create_user(self, user_data: Dict[str, Any], return_password: bool = False) -> Dict[str, Any]:
        """
        Create a new user in Azure AD.
        
        Args:
            user_data: Dictionary containing user information
            return_password: Whether to include the generated password in the response
            
        Returns:
            Dict containing creation result with user information or error details
        """
        if not self.access_token:
            return {
                "success": False,
                "message": "No access token available. Authentication required.",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        create_user_url = f"{self.graph_endpoint}/users"
        
        # Store the generated password if it was auto-generated
        generated_password = None
        if 'passwordProfile' in user_data and isinstance(user_data['passwordProfile'], dict):
            generated_password = user_data['passwordProfile'].get('password')
        
        try:
            response = requests.post(create_user_url, headers=headers, json=user_data)
            response.raise_for_status()
            
            created_user = response.json()
            
            # Build successful response
            result = {
                "success": True,
                "message": "User created successfully",
                "timestamp": datetime.utcnow().isoformat(),
                "user": {
                    "objectId": created_user.get('id'),
                    "userPrincipalName": created_user.get('userPrincipalName'),
                    "displayName": created_user.get('displayName'),
                    "mail": created_user.get('mail'),
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
                    "forceChangePasswordNextSignIn": user_data.get('passwordProfile', {}).get('forceChangePasswordNextSignIn', True),
                    "warning": "Store this password securely - it won't be available again"
                }
            
            logger.info(f"User created successfully: {created_user.get('userPrincipalName')}")
            return result
            
        except requests.exceptions.HTTPError as e:
            error_detail = "Unknown error"
            try:
                error_response = response.json()
                error_detail = error_response.get('error', {}).get('message', str(e))
            except:
                error_detail = str(e)
            
            logger.error(f"Error creating user: {error_detail}")
            return {
                "success": False,
                "message": f"User creation failed: {error_detail}",
                "timestamp": datetime.utcnow().isoformat(),
                "error": {
                    "type": "HTTP_ERROR",
                    "details": error_detail,
                    "statusCode": getattr(response, 'status_code', None)
                }
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error creating user: {e}")
            return {
                "success": False,
                "message": f"Network error: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
                "error": {
                    "type": "NETWORK_ERROR",
                    "details": str(e)
                }
            }

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
            logger.error(f"JSON file not found: {json_file_path}")
            return None
        
        with open(json_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        # Validate required structure
        if 'users' not in data or 'tenant_config' not in data:
            logger.error("Invalid JSON structure. Missing 'users' or 'tenant_config' sections.")
            return None
        
        logger.info(f"Loaded {len(data['users'])} users from {json_file_path}")
        return data
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON format: {e}")
        return None
    except Exception as e:
        logger.error(f"Error loading JSON file: {e}")
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
            logger.warning(f"Password for {user_info['displayName']} may not meet Azure AD requirements: {', '.join(issues)}")
    else:
        # Generate secure password
        password_length = tenant_config.get('password_length', 16)
        password = password_generator.generate_password(password_length)
        logger.info(f"Generated secure password for {user_info['displayName']}")
    
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
            logger.warning(f"Invalid GUID format for primary_tenant_id: {primary_tenant_id} for user {user_info['displayName']}")
    
    return user_data

def create_users_from_json(json_file_path: str = "sample_users.json", return_passwords: bool = False, 
                          output_file: str = None) -> Dict[str, Any]:
    """
    Create users in the external tenant from JSON file.
    
    Args:
        json_file_path: Path to the JSON file containing user data
        return_passwords: Whether to include generated passwords in the response
        output_file: Optional path to save JSON output to file
        
    Returns:
        Dictionary containing complete operation results in JSON format
    """
    operation_start = datetime.utcnow()
    
    # Load user data from JSON
    data = load_user_data(json_file_path)
    if not data:
        result = {
            "operation": {
                "success": False,
                "message": "Failed to load user data",
                "timestamp": operation_start.isoformat(),
                "duration": "0.00s"
            }
        }
        return result
    
    # Configuration - Replace with your actual values
    TENANT_ID = "598c44cc-c795-4d3b-9b71-ad77e74e1bdb"
    CLIENT_ID = os.getenv('AZURE_CLIENT_ID', "your-app-registration-client-id")
    CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET', "your-app-registration-secret")
    
    # Initialize the user creator
    user_creator = EntraUserCreator(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    
    # Get access token
    auth_result = user_creator.get_access_token()
    if not auth_result["success"]:
        result = {
            "operation": {
                "success": False,
                "message": "Authentication failed",
                "timestamp": operation_start.isoformat(),
                "duration": f"{(datetime.utcnow() - operation_start).total_seconds():.2f}s"
            },
            "authentication": auth_result
        }
        return result
    
    tenant_config = data['tenant_config']
    users_data = data['users']
    
    # Create users and collect results
    created_users = []
    failed_users = []
    
    for user_info in users_data:
        try:
            logger.info(f"Processing user: {user_info['displayName']}")
            
            # Transform user data for Azure AD
            user_data = transform_user_data(user_info, tenant_config)
            
            # Create the user
            creation_result = user_creator.create_user(user_data, return_password=return_passwords)
            
            if creation_result["success"]:
                created_users.append(creation_result)
            else:
                failed_users.append({
                    "displayName": user_info.get('displayName', 'Unknown'),
                    "error": creation_result
                })
                
        except KeyError as e:
            error_result = {
                "success": False,
                "message": f"Missing required field: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
                "error": {
                    "type": "MISSING_FIELD",
                    "details": str(e)
                }
            }
            failed_users.append({
                "displayName": user_info.get('displayName', 'Unknown'),
                "error": error_result
            })
        except Exception as e:
            error_result = {
                "success": False,
                "message": f"Unexpected error: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
                "error": {
                    "type": "UNEXPECTED_ERROR",
                    "details": str(e)
                }
            }
            failed_users.append({
                "displayName": user_info.get('displayName', 'Unknown'),
                "error": error_result
            })
    
    operation_end = datetime.utcnow()
    duration = (operation_end - operation_start).total_seconds()
    
    # Build comprehensive result
    result = {
        "operation": {
            "success": len(failed_users) == 0,
            "message": f"Processed {len(users_data)} users",
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
        "security_notes": {
            "passwords_included": return_passwords,
            "warning": "Handle generated passwords securely" if return_passwords else None
        }
    }
    
    # Save to file if requested
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            logger.info(f"Results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save results to file: {e}")
    
    return result

def create_single_user(display_name: str, email: str, given_name: str, surname: str, 
                      primary_tenant_id: str = None, password: str = None, 
                      return_password: bool = True) -> Dict[str, Any]:
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
        Dict containing user creation result in JSON format
    """
    operation_start = datetime.utcnow()
    
    # Configuration
    TENANT_ID = "598c44cc-c795-4d3b-9b71-ad77e74e1bdb"
    CLIENT_ID = os.getenv('AZURE_CLIENT_ID', "your-app-registration-client-id")
    CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET', "your-app-registration-secret")
    
    user_creator = EntraUserCreator(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    
    # Authenticate
    auth_result = user_creator.get_access_token()
    if not auth_result["success"]:
        return {
            "operation": {
                "success": False,
                "message": "Authentication failed",
                "timestamp": operation_start.isoformat(),
                "duration": f"{(datetime.utcnow() - operation_start).total_seconds():.2f}s"
            },
            "authentication": auth_result
        }
    
    # Generate secure password if not provided
    password_warnings = []
    if not password:
        password_generator = SecurePasswordGenerator()
        password = password_generator.generate_password()
        logger.info(f"Generated secure password for {display_name}")
    else:
        # Validate provided password
        password_generator = SecurePasswordGenerator()
        is_valid, issues = password_generator.validate_password_strength(password)
        if not is_valid:
            password_warnings = issues
            logger.warning(f"Provided password may not meet Azure AD requirements: {', '.join(issues)}")
    
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
            logger.info(f"Adding primary_tenant_id: {primary_tenant_id}")
        except ValueError:
            logger.warning(f"Invalid GUID format for primary_tenant_id: {primary_tenant_id}")
    
    # Create the user
    creation_result = user_creator.create_user(user_data, return_password=return_password)
    
    operation_end = datetime.utcnow()
    duration = (operation_end - operation_start).total_seconds()
    
    # Build comprehensive result
    result = {
        "operation": {
            "success": creation_result["success"],
            "message": creation_result["message"],
            "timestamp": operation_start.isoformat(),
            "duration": f"{duration:.2f}s"
        },
        "authentication": auth_result,
        "user_creation": creation_result
    }
    
    if password_warnings:
        result["password_warnings"] = password_warnings
    
    return result

if __name__ == "__main__":
    logger.info("Starting Azure External Tenant User Creator")
    
    # Option 1: Create users from JSON file with JSON output
    logger.info("Creating users from JSON file with secure passwords...")
    results = create_users_from_json("sample_users.json", return_passwords=True, output_file="user_creation_results.json")
    
    # Print JSON results to console
    print(json.dumps(results, indent=2, ensure_ascii=False))
    
    # Option 2: Create a single custom user (uncomment to use)
    # logger.info("Creating custom user with generated secure password...")
    # custom_result = create_single_user(
    #     display_name="Alice Johnson",
    #     email="alice.johnson@yourdomain.onmicrosoft.com",
    #     given_name="Alice",
    #     surname="Johnson",
    #     primary_tenant_id="11111111-2222-3333-4444-555555555555",
    #     return_password=True
    # )
    # print(json.dumps(custom_result, indent=2, ensure_ascii=False))