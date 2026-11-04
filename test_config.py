# test_config.py
from security_engine import MailerService

# Enter your personal test email address here:
test_receiver = "your_personal_email@gmail.com"

print("Dispatching test verification email...")
success = MailerService.send_otp_email(test_receiver, "482910")

if success:
    print("Success: Test OTP email delivered successfully.")
else:
    print("Failed: Unable to send email. Verify your Gmail address and 16-character App Password.")