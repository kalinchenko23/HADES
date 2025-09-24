from pymetasploit3.msfrpc import MsfRpcClient

# --- CONFIGURATION ---
MSF_HOST = '192.168.34.131' # <-- IMPORTANT: Put your VM's IP here!
MSF_PORT = 55553
MSF_USER = 'msf'
MSF_PASS = 'my-super-secret-password'
USE_SSL = True
# --- END CONFIGURATION ---

print(f"Attempting to connect to {MSF_HOST}:{MSF_PORT}...")

try:
    client = MsfRpcClient(
        password=MSF_PASS,
        server=MSF_HOST,
        port=MSF_PORT,
        ssl=USE_SSL,
        user=MSF_USER
    )
    print("✅ SUCCESS: Connection established and client object created.")
    
    if client.authenticated:
        print("✅ SUCCESS: Authentication successful.")
    else:
        print("❌ FAILED: Authentication failed. Check username and password.")

except Exception as e:
    print(f"❌ FAILED: An error occurred during connection.")
    print(f"   Error Type: {type(e).__name__}")
    print(f"   Error Details: {e}")
