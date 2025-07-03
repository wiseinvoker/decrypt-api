# api/decrypt.py
import base64
import json
import os
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs

# Cross-platform encryption imports
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError:
    print("Missing pycryptodome dependency")
    AES = None


def decrypt_password(os_type, encrypted_password, enc_key):
    """
    Decrypt password using the provided encryption key
    """
    encrypted_key = enc_key
    
    if os_type == "win32":
        # For Windows, we can't use win32crypt on Vercel, so we'll handle the key differently
        # Remove 'DPAPI' prefix (first 5 bytes) if present
        if encrypted_key[:5] == b'DPAPI':
            encrypted_key = encrypted_key[5:]
        
        # Since we can't use DPAPI on Vercel, we'll assume the key is already decrypted
        # or handle it as a raw key
        key = encrypted_key
    else:
        # For macOS/Linux, handle the key
        key = encrypted_key[5:] if encrypted_key[:5] == b'DPAPI' else encrypted_key

    # Decrypt the password
    try:
        # Check for new encryption format (v10/v11)
        if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':
            # New encryption (AES-GCM)
            iv = encrypted_password[3:15]  # 12 bytes IV
            ciphertext = encrypted_password[15:]
            
            # Create AES-GCM cipher
            cipher = AES.new(key, AES.MODE_GCM, iv)
            
            # Decrypt (last 16 bytes are authentication tag)
            decrypted = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
            return decrypted.decode('utf-8')
        else:
            # For older formats or non-Windows systems
            # Try to decode as plain text (fallback)
            try:
                return encrypted_password.decode('utf-8', errors='ignore')
            except:
                return ""
                
    except Exception as e:
        print(f"Error decrypting password: {e}")
        return ""


def create_sample_encrypted_data(password, master_key):
    """
    Create sample encrypted data for testing (AES-GCM format)
    """
    try:
        # Create a 12-byte IV
        iv = os.urandom(12)
        
        # Use the master key directly (assuming it's 32 bytes)
        if len(master_key) != 32:
            # If not 32 bytes, pad or derive a proper key
            from Crypto.Protocol.KDF import PBKDF2
            key = PBKDF2(master_key, b'salt', 32, count=1000, hmac_hash_module=SHA256)
        else:
            key = master_key
            
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        
        # Encrypt the password
        ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
        
        # Combine v10 prefix + IV + ciphertext + tag
        encrypted_data = b'v10' + iv + ciphertext + tag
        
        return base64.b64encode(encrypted_data).decode('utf-8')
        
    except Exception as e:
        return f"Error creating sample data: {e}"


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_POST(self):
        """Handle POST requests"""
        try:
            # Set CORS headers
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            # Parse JSON data
            try:
                data = json.loads(post_data)
            except json.JSONDecodeError:
                self.send_error_response(400, "Invalid JSON format")
                return
            
            # Extract parameters
            action = data.get('action')
            encrypted_password = data.get('encrypted_password')
            master_key = data.get('master_key')
            os_type = data.get('os_type', 'linux')  # Default to linux for Vercel
            
            if action == 'decrypt':
                if not encrypted_password or not master_key:
                    self.send_error_response(400, "encrypted_password and master_key are required")
                    return
                
                # Decode base64 inputs
                try:
                    enc_password_bytes = base64.b64decode(encrypted_password)
                    master_key_bytes = base64.b64decode(master_key)
                except Exception as e:
                    self.send_error_response(400, f"Invalid base64 encoding: {e}")
                    return
                
                # Decrypt password
                decrypted = decrypt_password(os_type, enc_password_bytes, master_key_bytes)
                
                response = {
                    'success': True,
                    'decrypted_password': decrypted,
                    'os_type': os_type
                }
                
                self.send_json_response(200, response)
                
            elif action == 'create_sample':
                # Create sample encrypted data for testing
                password = data.get('password', 'test123')
                master_key = data.get('master_key_raw', 'sample_master_key_32_bytes_long!!')
                
                if len(master_key) < 32:
                    master_key = master_key.ljust(32, '0')
                
                encrypted_sample = create_sample_encrypted_data(password, master_key.encode())
                
                response = {
                    'success': True,
                    'encrypted_password': encrypted_sample,
                    'master_key': base64.b64encode(master_key.encode()).decode(),
                    'original_password': password
                }
                
                self.send_json_response(200, response)
                
            else:
                self.send_error_response(400, "Invalid action. Use 'decrypt' or 'create_sample'")
                
        except Exception as e:
            self.send_error_response(500, f"Internal server error: {str(e)}")

    def do_GET(self):
        """Handle GET requests - return API documentation"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        docs = {
            'message': 'Password Decryption API',
            'endpoints': {
                'POST /api/decrypt': {
                    'description': 'Decrypt password using master key',
                    'parameters': {
                        'action': 'decrypt',
                        'encrypted_password': 'base64 encoded encrypted password',
                        'master_key': 'base64 encoded master key',
                        'os_type': 'optional: win32, darwin, or linux (default: linux)'
                    }
                },
                'POST /api/decrypt (create_sample)': {
                    'description': 'Create sample encrypted data for testing',
                    'parameters': {
                        'action': 'create_sample',
                        'password': 'plain text password to encrypt',
                        'master_key_raw': 'master key as string'
                    }
                }
            },
            'example_requests': [
                {
                    'action': 'create_sample',
                    'password': 'mypassword123',
                    'master_key_raw': 'my_secret_master_key_32_chars!!'
                },
                {
                    'action': 'decrypt',
                    'encrypted_password': 'base64_encrypted_data',
                    'master_key': 'base64_master_key',
                    'os_type': 'linux'
                }
            ]
        }
        
        self.wfile.write(json.dumps(docs, indent=2).encode('utf-8'))

    def send_json_response(self, status_code, data):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def send_error_response(self, status_code, message):
        """Send error response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        error_data = {'success': False, 'error': message}
        self.wfile.write(json.dumps(error_data).encode('utf-8'))
