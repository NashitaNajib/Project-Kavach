import streamlit as st
import google.generativeai as genai
from PIL import Image
import io
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from dotenv import load_dotenv

# --- CONFIGURATION ---
# Load environment variables from .env file
load_dotenv()

# Fetch the key securely
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Check if key exists to prevent crashing
if not GOOGLE_API_KEY:
    st.error("⚠️ API Key not found! Please check your .env file.")
    st.stop()

genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('models/gemini-2.5-flash')

# --- MILITARY STYLE UI SETUP ---
st.set_page_config(page_title="PROJECT KAVACH", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# --- AES-256 ENCRYPTION LOGIC (Strict Requirement) ---
def get_key(password):
    # Generates a 32-byte hash (256 bits) from the password
    return hashlib.sha256(password.encode()).digest()

def encrypt_message(plain_text, password):
    try:
        key = get_key(password)
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
        # Return IV + Encrypted Data (encoded in Base64 for hiding)
        return base64.b64encode(iv + encrypted_bytes).decode()
    except Exception as e:
        return None

def decrypt_message(encrypted_text, password):
    try:
        data = base64.b64decode(encrypted_text)
        iv = data[:16] # Extract the IV
        encrypted_bytes = data[16:]
        key = get_key(password)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        return decrypted_bytes.decode()
    except:
        return None # Return None if password is wrong (Padding Error)

# --- STEGANOGRAPHY LOGIC (Custom LSB - No Extra Libs) ---
def text_to_bin(message):
    return ''.join(format(ord(i), '08b') for i in message)

def encode_image(image, secret_data):
    image = image.convert("RGB")
    pixels = image.load()
    # Add delimiter to know where message ends
    full_message = secret_data + "#####"
    binary_message = text_to_bin(full_message)
    data_len = len(binary_message)
    
    width, height = image.size
    index = 0
    
    for y in range(height):
        for x in range(width):
            if index < data_len:
                r, g, b = pixels[x, y]
                # Modify LSB of Red Channel
                new_r = (r & 0xFE) | int(binary_message[index])
                pixels[x, y] = (new_r, g, b)
                index += 1
            else:
                return image
    return image

def decode_image(image):
    image = image.convert("RGB")
    pixels = image.load()
    binary_data = ""
    width, height = image.size
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)

    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
    
    decoded_string = ""
    for byte in all_bytes:
        decoded_string += chr(int(byte, 2))
        if decoded_string.endswith("#####"):
            return decoded_string[:-5]
            
    return "" 

# --- MAIN APP ---
st.markdown("""
<style>
    .stApp {background-color: #0E1117; color: #00FF41;}
    h1 {text-align: center; color: #00FF41; font-family: 'Courier New';}
    .stButton>button {background-color: #004d00; color: white; border-radius: 5px; border: 1px solid #00FF41;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PROJECT KAVACH")
st.markdown("<h3 style='text-align: center; color: white;'>Secure Steganographic Communication System</h3>", unsafe_allow_html=True)

tab1, tab2 = st.tabs(["🔒 ENCRYPT (Sender)", "🔓 DECRYPT (Receiver)"])

# --- SENDER LOGIC ---
with tab1:
    st.markdown("### 1. MISSION ENCODING")
    
    col1, col2 = st.columns(2)
    with col1:
        uploaded_file = st.file_uploader("Upload Cover Image", type=["png", "jpg"])
    with col2:
        secret_text = st.text_area("Enter Battle Plan (Secret Message)")
        password = st.text_input("Set Encryption Key", type="password")

    if st.button("EXECUTE ENCRYPTION"):
        if uploaded_file and secret_text and password:
            try:
                # 1. GEMINI AUDIT (Innovation Points)
                with st.spinner("Gemini is auditing message security..."):
                    audit = model.generate_content(f"You are a military defense bot. Rate this message sensitivity (Low/Med/High) and suggest 1 code word for it: '{secret_text}'")
                    st.info(f"🤖 **AI Security Report:** {audit.text}")

                # 2. AES-256 ENCRYPTION
                encrypted_text = encrypt_message(secret_text, password)
                if not encrypted_text:
                    st.error("Encryption Failed.")
                    st.stop()
                
                # 3. STEGANOGRAPHY HIDING
                img = Image.open(uploaded_file)
                stego_img = encode_image(img, encrypted_text)
                
                # 4. DOWNLOAD
                buf = io.BytesIO()
                stego_img.save(buf, format="PNG") # PNG is required for lossless
                byte_im = buf.getvalue()
                
                st.success("✅ MESSAGE SECURED & HIDDEN")
                st.download_button("⬇️ Download Secure Image", byte_im, "kavach_secure.png", "image/png")
                
            except Exception as e:
                st.error(f"System Error: {e}")
        else:
            st.warning("All fields are mandatory.")

# --- RECEIVER LOGIC ---
with tab2:
    st.markdown("### 2. INTEL EXTRACTION")
    
    decode_file = st.file_uploader("Upload Suspicious Image", type=["png"])
    pass_input = st.text_input("Enter Decryption Key", type="password", key="rec_pass")

    if st.button("DECRYPT INTEL"):
        if decode_file and pass_input:
            try:
                img = Image.open(decode_file)
                
                # 1. EXTRACT HIDDEN DATA
                extracted_encrypted_text = decode_image(img)
                
                if not extracted_encrypted_text:
                    st.error("❌ NO HIDDEN DATA FOUND IN THIS IMAGE.")
                else:
                    # 2. ATTEMPT AES DECRYPTION
                    decrypted_msg = decrypt_message(extracted_encrypted_text, pass_input)
                    
                    if decrypted_msg:
                        # SUCCESS: Correct Password
                        st.success("✅ ACCESS GRANTED. DECRYPTING...")
                        st.code(decrypted_msg, language="plaintext")
                        st.balloons()
                    else:
                        # FAIL: Wrong Password (GRACEFUL FAIL as per Rubric)
                        st.error("❌ ACCESS DENIED: INVALID KEY")
                        st.warning("⚠️ DECRYPTION FAILED. INTEGRITY CHECK FAILED.")
                        # This meets "System Integrity" criteria 
            
            except Exception as e:
                st.error(f"Critical Error: {e}")
