import pyotp
import qrcode


def generate_secret_key():
    """
    Generate a random secret key for TOTP.
    """
    secret = pyotp.random_base32()
    print(f"[INFO] Your secret key is: {secret}")
    return secret

def generate_qr_code(secret, user_email, issuer_name="2FA System"):
    """
    Generate a QR code for the secret key to be used with an authenticator app.
    """
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user_email, issuer_name=issuer_name)
    qr = qrcode.make(totp_uri)
    qr_code_filename = "totp_qr_code.png"
    qr.save(qr_code_filename)
    print(f"[INFO] QR Code has been saved as '{qr_code_filename}'. Scan it with an authenticator app like Google Authenticator.")

def verify_otp(secret):
    """
    Verify the OTP input by the user.
    """
    totp = pyotp.TOTP(secret)
    otp_input = input("Enter the OTP from your authenticator app: ")
    if totp.verify(otp_input):
        print("[SUCCESS] Authentication successful!")
    else:
        print("[ERROR] Authentication failed. Please try again.")

def main():
    """
    Main function to run the 2FA project.
    """
    print("[INFO] Welcome to the Two-Factor Authentication (2FA) System.")
    user_email = input("Please enter your email address: ")

    # Generate Secret Key
    secret = generate_secret_key()

    # Generate QR Code for Authenticator Setup
    generate_qr_code(secret, user_email)

    #  Wait for user to set up
    print("[INFO] Please set up your authenticator app and then press ENTER to continue.")
    input()

    #  OTP Verification
    for _ in range(3):  # Allow up to 3 attempts for OTP verification
        verify_otp(secret)
        if pyotp.TOTP(secret).verify(input("Enter OTP again to verify: ")):
            break
        else:
            print("[ERROR] Incorrect OTP, please try again.")

    # Conclusion
    print("[INFO] Thank you for using the 2FA System. Ensure you keep your authenticator app safe.")

if __name__ == "__main__":
    main()
