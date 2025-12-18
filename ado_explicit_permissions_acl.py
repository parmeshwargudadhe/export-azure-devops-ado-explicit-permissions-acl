import base64
import requests
from openpyxl import Workbook

# ==============================
# CONFIG
# ==============================
ORG = "myado-org"
PAT = "myado-pat"
API_VERSION = "7.1-preview.1"

# ==============================
# AUTH HEADER
# ==============================
def get_headers():
    token = base64.b64encode(f":{PAT}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json"
    }

# ==============================
# 1. GET ALL SECURITY NAMESPACES
# ==============================
def get_all_security_namespaces():
    """Fetches all security namespace definitions from the organization."""
    url = f"https://dev.azure.com/{ORG}/_apis/securitynamespaces?api-version={API_VERSION}"
    response = requests.get(url, headers=get_headers())
    response.raise_for_status()
    return response.json().get("value", [])

# ==============================
# 2. GET ACLs FOR A NAMESPACE (UPDATED LOGIC)
# ==============================
def get_acls_for_namespace(namespace_id, token_filter=""):
    """
    Returns ACLs for a specific security namespace.
    The 'token' parameter can filter for a specific resource path.
    """
    base_url = f"https://dev.azure.com/{ORG}/_apis/accesscontrollists/{namespace_id}?api-version={API_VERSION}"
    if token_filter:
        url = f"{base_url}&token={token_filter}"
    else:
        url = base_url

    response = requests.get(url, headers=get_headers())
    if response.status_code == 404:
        # Some namespaces might not have any ACLs defined; this is normal.
        return []
    response.raise_for_status()
    return response.json().get("value", [])

# ==============================
# 3. RESOLVE DESCRIPTOR TO IDENTITY NAME
# ==============================
def resolve_descriptor_to_identity(descriptor):
    """
    Attempts to resolve a descriptor to a human-readable identity name.
    Handles multiple descriptor formats and API endpoints.
    """
    identity_endpoints = [
        f"https://vssps.dev.azure.com/{ORG}/_apis/graph/descriptors/{descriptor}",
        f"https://vssps.dev.azure.com/{ORG}/_apis/graph/identities/{descriptor}",
    ]
    
    for endpoint in identity_endpoints:
        url = f"{endpoint}?api-version={API_VERSION}"
        response = requests.get(url, headers=get_headers())
        if response.status_code == 200:
            data = response.json()
            # The 'displayName' field is commonly used for the readable name
            return data.get("displayName", descriptor)
        elif response.status_code not in (400, 404):
            # If it's an unexpected error, raise it
            response.raise_for_status()
    # If all endpoints fail, return the original descriptor
    return descriptor

# ==============================
# 4. GET PERMISSION BIT NAMES (OPTIONAL)
# ==============================
def get_permission_bit_names(allow_bits, namespace_actions):
    """
    Converts a numeric 'allow' or 'deny' bitmask into a list of permission names.
    """
    permission_names = []
    for action in namespace_actions:
        if action.get("bit", 0) & allow_bits:
            permission_names.append(action.get("displayName", action.get("name", "UNKNOWN")))
    return ", ".join(permission_names) if permission_names else "None"

# ==============================
# MAIN
# ==============================
def main():
    print("🔍 Starting comprehensive permission scan...")

    # Step 1: Get all namespaces
    print("  Fetching all security namespace definitions...")
    all_namespaces = get_all_security_namespaces()
    print(f"  Found {len(all_namespaces)} security namespaces.")

    # Prepare the Excel workbook and sheet
    wb = Workbook()
    ws = wb.active
    ws.title = "All Explicit Permissions"
    # Updated headers to include more context
    ws.append([
        "Security Namespace",
        "Namespace Display Name",
        "Resource Token",
        "Identity Descriptor",
        "Identity Name",
        "Allow Permissions (Bits)",
        "Allow Permissions (Names)",
        "Deny Permissions (Bits)",
        "Deny Permissions (Names)"
    ])

    total_acl_entries = 0
    # Step 2: Iterate through each namespace
    for namespace in all_namespaces:
        namespace_id = namespace.get("namespaceId")
        namespace_name = namespace.get("name")
        namespace_display_name = namespace.get("displayName")
        namespace_actions = namespace.get("actions", [])
        
        print(f"  Querying namespace: {namespace_display_name} ({namespace_name})...")

        # Fetch ACLs for this namespace
        acls = get_acls_for_namespace(namespace_id)
        
        # Step 3: Process each ACL in the namespace
        for acl in acls:
            token = acl.get("token", "")
            aces_dict = acl.get("acesDictionary", {})
            
            for descriptor, ace in aces_dict.items():
                allow = ace.get("allow", 0)
                deny = ace.get("deny", 0)
                
                # Skip entries with no explicit permissions (both allow and deny are 0)
                if allow == 0 and deny == 0:
                    continue
                
                # Resolve the descriptor to a readable name
                identity_name = resolve_descriptor_to_identity(descriptor)
                
                # Get permission names for allow and deny bits (optional but helpful)
                allow_names = get_permission_bit_names(allow, namespace_actions)
                deny_names = get_permission_bit_names(deny, namespace_actions)
                
                # Write the row to Excel
                ws.append([
                    namespace_name,
                    namespace_display_name,
                    token,
                    descriptor,
                    identity_name,
                    allow,
                    allow_names,
                    deny,
                    deny_names
                ])
                total_acl_entries += 1

    # Save the workbook
    output_filename = f"azure_devops_complete_permissions_{ORG}.xlsx"
    wb.save(output_filename)
    print(f"✅ Scan complete. Found {total_acl_entries} explicit permission entries.")
    print(f"📁 Report saved as: {output_filename}")

# ==============================
if __name__ == "__main__":
    main()
