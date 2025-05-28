<#
.SYNOPSIS
    Query Microsoft Graph API to retrieve external users with custom attributes
.DESCRIPTION
    Retrieves user displayName, email address, and primary_tenant_id custom attribute
    from Azure AD using Microsoft Graph API following Azure best practices
.EXAMPLE
    .\graph.ps1
#>

# Function to load environment variables from .env file following Azure best practices
function Import-EnvFile {
    param(
        [string]$EnvFilePath = ".env"
    )
    
    Write-Host "🔍 Loading Azure configuration from .env file..." -ForegroundColor Yellow
    
    if (-not (Test-Path $EnvFilePath)) {
        Write-Warning "⚠️  .env file not found at: $EnvFilePath"
        Write-Host "📝 Please create a .env file with the following format:" -ForegroundColor Yellow
        Write-Host "AZURE_TENANT_ID=your-tenant-id" -ForegroundColor Gray
        Write-Host "AZURE_CLIENT_ID=your-client-id" -ForegroundColor Gray
        Write-Host "AZURE_CLIENT_SECRET=your-client-secret" -ForegroundColor Gray
        return $false
    }
    
    try {
        # Read and parse .env file following Azure security best practices
        $envContent = Get-Content $EnvFilePath -ErrorAction Stop
        $envVars = @{}
        
        foreach ($line in $envContent) {
            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                continue
            }
            
            # Parse key=value pairs, handling quoted values
            if ($line -match '^([^=]+)=(.*)$') {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                
                # Remove quotes if present (both single and double quotes)
                if (($value.StartsWith('"') -and $value.EndsWith('"')) -or 
                    ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                    $value = $value.Substring(1, $value.Length - 2)
                }
                
                $envVars[$key] = $value
                
                # Set environment variable for current session
                [Environment]::SetEnvironmentVariable($key, $value, [EnvironmentVariableTarget]::Process)
            }
        }
        
        Write-Host "✅ Successfully loaded $($envVars.Count) environment variables from .env" -ForegroundColor Green
        
        # Validate required Azure variables are present
        $requiredVars = @('AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET')
        $missingVars = @()
        
        foreach ($var in $requiredVars) {
            if (-not $envVars.ContainsKey($var) -or [string]::IsNullOrWhiteSpace($envVars[$var])) {
                $missingVars += $var
            } else {
                # Mask sensitive information in logs
                $maskedValue = if ($var -eq 'AZURE_CLIENT_SECRET') { 
                    "***MASKED***" 
                } else { 
                    $envVars[$var].Substring(0, [Math]::Min(8, $envVars[$var].Length)) + "..." 
                }
                Write-Host "   $var`: $maskedValue" -ForegroundColor Cyan
            }
        }
        
        if ($missingVars.Count -gt 0) {
            Write-Error "❌ Missing required environment variables: $($missingVars -join ', ')"
            return $false
        }
        
        return $true
        
    } catch {
        Write-Error "❌ Failed to load .env file: $($_.Exception.Message)"
        return $false
    }
}

# Import required modules following Azure best practices
try {
    Write-Host "📦 Importing Microsoft Graph modules..." -ForegroundColor Yellow
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Write-Host "✅ Microsoft Graph modules imported successfully" -ForegroundColor Green
} catch {
    Write-Error "❌ Failed to import required modules. Please install Microsoft Graph PowerShell SDK:"
    Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}

# Load Azure configuration from .env file following Azure best practices
$envLoaded = Import-EnvFile -EnvFilePath ".env"

if (-not $envLoaded) {
    Write-Host "🔄 Falling back to manual configuration..." -ForegroundColor Yellow
}

# Azure configuration - Load from environment variables with fallback to prompts
$TenantId = $env:AZURE_TENANT_ID
$ClientId = $env:AZURE_CLIENT_ID
$ClientSecret = $env:AZURE_CLIENT_SECRET

# Validate and prompt for missing values following Azure security best practices
if (-not $TenantId) {
    $TenantId = Read-Host "Enter your Azure Tenant ID"
}

if (-not $ClientId) {
    $ClientId = Read-Host "Enter your Azure Client ID"
}

if (-not $ClientSecret) {
    $ClientSecret = Read-Host "Enter your Azure Client Secret" -AsSecureString
    $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))
}

# Validate GUID format for Azure identifiers
function Test-AzureGuid {
    param([string]$Guid, [string]$Name)
    
    try {
        [System.Guid]::Parse($Guid) | Out-Null
        return $true
    } catch {
        Write-Error "❌ Invalid $Name format. Must be a valid GUID."
        return $false
    }
}

if (-not (Test-AzureGuid -Guid $TenantId -Name "Tenant ID") -or 
    -not (Test-AzureGuid -Guid $ClientId -Name "Client ID")) {
    exit 1
}

Write-Host "`n🔍 Connecting to Microsoft Graph API..." -ForegroundColor Yellow
Write-Host "🏢 Tenant: $($TenantId.Substring(0,8))..." -ForegroundColor Cyan
Write-Host "🔑 Client: $($ClientId.Substring(0,8))..." -ForegroundColor Cyan

try {
    # Connect to Microsoft Graph using client credentials flow
    # Following Azure best practices for service principal authentication
    $secureClientSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($ClientId, $secureClientSecret)
    
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop
    
    Write-Host "✅ Successfully connected to Microsoft Graph" -ForegroundColor Green
    
    # Get current context to verify connection following Azure best practices
    $context = Get-MgContext
    Write-Host "📋 Connected to tenant: $($context.TenantId)" -ForegroundColor Cyan
    Write-Host "🔑 Using app: $($context.ClientId)" -ForegroundColor Cyan
    Write-Host "🌐 Graph endpoint: $($context.Environment)" -ForegroundColor Cyan
    
} catch {
    Write-Error "❌ Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    
    # Enhanced troubleshooting guidance following Azure best practices
    if ($_.Exception.Message -like "*AADSTS7000215*") {
        Write-Host "🔧 Troubleshooting: Invalid client secret provided" -ForegroundColor Yellow
        Write-Host "   - Verify the client secret is correct and hasn't expired" -ForegroundColor Yellow
        Write-Host "   - Check if the app registration exists in the correct tenant" -ForegroundColor Yellow
    } elseif ($_.Exception.Message -like "*AADSTS70011*") {
        Write-Host "🔧 Troubleshooting: Invalid scope or permissions" -ForegroundColor Yellow
        Write-Host "   - Ensure the app has required Graph API permissions" -ForegroundColor Yellow
        Write-Host "   - Verify admin consent has been granted" -ForegroundColor Yellow
    }
    
    exit 1
}

Write-Host "`n🔍 Querying users from Microsoft Graph API..." -ForegroundColor Yellow

try {
    # Query users with extension attributes following Azure best practices
    # Using $select to optimize query performance and $filter for external users
    $users = Get-MgUser -All `
        -Property "displayName,mail,otherMails,userType,onPremisesExtensionAttributes,userPrincipalName,id,createdDateTime" `
        -Filter "userType eq 'Guest'" `
        -ErrorAction Stop
    
    Write-Host "📊 Found $($users.Count) external users" -ForegroundColor Green
    
    # Process and format results following Azure best practices
    $results = @()
    
    foreach ($user in $users) {
        # Extract primary_tenant_id from extension attributes
        $primaryTenantId = $null
        
        if ($user.OnPremisesExtensionAttributes) {
            # Check extensionAttribute1 where we store primary_tenant_id
            $primaryTenantId = $user.OnPremisesExtensionAttributes.ExtensionAttribute1
        }
        
        # Determine email address - prefer mail field, fallback to otherMails
        $emailAddress = $user.Mail
        if (-not $emailAddress -and $user.OtherMails -and $user.OtherMails.Count -gt 0) {
            $emailAddress = $user.OtherMails[0]
        }
        
        # Create result object following Azure data conventions
        $result = [PSCustomObject]@{
            DisplayName       = $user.DisplayName
            EmailAddress      = $emailAddress
            PrimaryTenantId   = $primaryTenantId
            UserType          = $user.UserType
            UserPrincipalName = $user.UserPrincipalName
            ObjectId          = $user.Id
            CreatedDateTime   = $user.CreatedDateTime
        }
        
        $results += $result
    }
    
    # Display results in formatted table following Azure reporting best practices
    Write-Host "`n📄 External Users with Custom Attributes:" -ForegroundColor Cyan
    Write-Host "=" * 100 -ForegroundColor Cyan
    
    if ($results.Count -gt 0) {
        # Primary results table
        $results | Format-Table -Property DisplayName, EmailAddress, PrimaryTenantId -AutoSize
        
        # Additional detailed output for troubleshooting
        Write-Host "`n🔍 Detailed Information:" -ForegroundColor Yellow
        $results | Format-List -Property DisplayName, EmailAddress, PrimaryTenantId, UserType, UserPrincipalName, ObjectId, CreatedDateTime
        
        # Export to CSV for further analysis following Azure data management best practices
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $csvPath = "ExternalUsers_$timestamp.csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "💾 Results exported to: $csvPath" -ForegroundColor Green
        
        # Summary statistics following Azure reporting best practices
        $usersWithPrimaryTenant = ($results | Where-Object { $_.PrimaryTenantId }).Count
        $usersWithoutPrimaryTenant = $results.Count - $usersWithPrimaryTenant
        $usersWithEmail = ($results | Where-Object { $_.EmailAddress }).Count
        
        Write-Host "`n📊 Summary Report:" -ForegroundColor Cyan
        Write-Host "   Total external users: $($results.Count)" -ForegroundColor White
        Write-Host "   With primary_tenant_id: $usersWithPrimaryTenant" -ForegroundColor Green
        Write-Host "   Without primary_tenant_id: $usersWithoutPrimaryTenant" -ForegroundColor Yellow
        Write-Host "   With email addresses: $usersWithEmail" -ForegroundColor Green
        
        # Azure compliance and governance insights
        if ($usersWithoutPrimaryTenant -gt 0) {
            Write-Host "`n⚠️  Governance Alert: $usersWithoutPrimaryTenant external users lack primary_tenant_id attribute" -ForegroundColor Yellow
            Write-Host "   Consider updating these users with proper tenant identification for compliance" -ForegroundColor Yellow
        }
        
    } else {
        Write-Host "ℹ️  No external users found in the tenant" -ForegroundColor Yellow
        Write-Host "   This could indicate:" -ForegroundColor Gray
        Write-Host "   - No B2B users have been invited" -ForegroundColor Gray
        Write-Host "   - Users may have userType 'Member' instead of 'Guest'" -ForegroundColor Gray
    }
    
} catch {
    Write-Error "❌ Failed to query users: $($_.Exception.Message)"
    
    # Enhanced troubleshooting following Azure best practices
    if ($_.Exception.Message -like "*Insufficient privileges*") {
        Write-Host "`n🔧 Required Azure App Registration Permissions:" -ForegroundColor Yellow
        Write-Host "   Application Permissions (requires admin consent):" -ForegroundColor Yellow
        Write-Host "   - User.Read.All" -ForegroundColor Cyan
        Write-Host "   - Directory.Read.All" -ForegroundColor Cyan
        Write-Host "`n   To grant permissions:" -ForegroundColor Yellow
        Write-Host "   1. Go to Azure Portal > App Registrations" -ForegroundColor Gray
        Write-Host "   2. Select your app > API Permissions" -ForegroundColor Gray
        Write-Host "   3. Add the required Microsoft Graph permissions" -ForegroundColor Gray
        Write-Host "   4. Click 'Grant admin consent'" -ForegroundColor Gray
    }
}

# Cleanup following Azure security best practices
Write-Host "`n🧹 Cleaning up connection..." -ForegroundColor Yellow

try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Write-Host "✅ Disconnected from Microsoft Graph" -ForegroundColor Green
} catch {
    Write-Warning "⚠️  Could not properly disconnect from Microsoft Graph"
}

# Clear sensitive variables from memory following Azure security best practices
$ClientSecret = $null
[System.GC]::Collect()

Write-Host "`n🎉 Script completed successfully!" -ForegroundColor Green
Write-Host "📋 Check the generated CSV file for detailed user information" -ForegroundColor Cyan