# api/decrypt.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import os

# Cross-platform encryption imports
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError:
    print("Missing pycryptodome dependency")
    AES = None

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes


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


@app.route('/', methods=['GET'])
def get_docs():
    """API Documentation"""
    docs = {
        'message': 'Password Decryption API',
        'version': '1.0.0',
        'endpoints': {
            'GET /': {
                'description': 'API documentation'
            },
            'POST /decrypt': {
                'description': 'Decrypt password using master key',
                'parameters': {
                    'encrypted_password': 'base64 encoded encrypted password',
                    'master_key': 'base64 encoded master key',
                    'os_type': 'optional: win32, darwin, or linux (default: linux)'
                }
            },
            'POST /create-sample': {
                'description': 'Create sample encrypted data for testing',
                'parameters': {
                    'password': 'plain text password to encrypt',
                    'master_key_raw': 'master key as string'
                }
            }
        },
        'example_requests': [
            {
                'endpoint': 'POST /create-sample',
                'body': {
                    'password': 'mypassword123',
                    'master_key_raw': 'my_secret_master_key_32_chars!!'
                }
            },
            {
                'endpoint': 'POST /decrypt',
                'body': {
                    'encrypted_password': 'base64_encrypted_data',
                    'master_key': 'base64_master_key',
                    'os_type': 'linux'
                }
            }
        ]
    }
    
    return jsonify(docs)


@app.route('/decrypt', methods=['POST'])
def decrypt_endpoint():
    """Decrypt password endpoint"""
    try:
        data = request.get_json()
        print(data)
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        # Extract parameters
        encrypted_password = data.get('encrypted_password')
        master_key = data.get('master_key')
        os_type = data.get('os_type', 'linux')  # Default to linux for Vercel
        
        if not encrypted_password or not master_key:
            return jsonify({
                'success': False,
                'error': 'encrypted_password and master_key are required'
            }), 400
        
        # Decode base64 inputs
        try:
            enc_password_bytes = base64.b64decode(encrypted_password)
            master_key_bytes = base64.b64decode(master_key)
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Invalid base64 encoding: {str(e)}'
            }), 400
        
        # Decrypt password
        decrypted = decrypt_password(os_type, enc_password_bytes, master_key_bytes)
        
        return jsonify({
            'success': True,
            'decrypted_password': decrypted,
            'os_type': os_type
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@app.route('/create-sample', methods=['POST'])
def create_sample_endpoint():
    """Create sample encrypted data for testing"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        # Extract parameters
        password = data.get('password', 'test123')
        master_key_raw = data.get('master_key_raw', 'sample_master_key_32_bytes_long!!')
        
        # Ensure master key is 32 bytes
        if len(master_key_raw) < 32:
            master_key_raw = master_key_raw.ljust(32, '0')
        elif len(master_key_raw) > 32:
            master_key_raw = master_key_raw[:32]
        
        # Create sample encrypted data
        encrypted_sample = create_sample_encrypted_data(password, master_key_raw.encode())
        
        return jsonify({
            'success': True,
            'encrypted_password': encrypted_sample,
            'master_key': base64.b64encode(master_key_raw.encode()).decode(),
            'original_password': password,
            'info': 'Use these values with the /decrypt endpoint'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'password-decryption-api',
        'version': '1.0.0'
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found'
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'success': False,
        'error': 'Method not allowed'
    }), 405


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500


# For Vercel
if __name__ == '__main__':
    app.run(debug=True)
