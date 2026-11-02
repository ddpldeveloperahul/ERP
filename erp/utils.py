import logging
from django.core.mail import send_mail
from django.conf import settings
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired

logger = logging.getLogger(__name__)
signer = TimestampSigner()


def send_otp_email(email, otp, purpose="SIGNUP"):
    """
    Sends an OTP verification email to the user using configured SMTP settings.
    purpose: 'SIGNUP' or 'FORGOT_PASSWORD'
    Returns (True, None) on success or (False, error_message) on failure.
    """
    if purpose == "FORGOT_PASSWORD":
        subject = "DR. DESIGN ERP - Password Reset OTP"
        headline = "Reset Your Password"
        sub_title = "Password Reset Request"
        intro_text = (
            "We received a request to reset your password for your DR. DESIGN ERP account. "
            "Use the verification code below to verify your identity and set a new password:"
        )
        notice_text = (
            "If you did not request a password reset, please ignore this email or contact "
            "your system administrator immediately. Your account remains completely secure."
        )
        plain_message = (
            f"Hello,\n\n"
            f"We received a request to reset your password for your DR. DESIGN ERP account.\n\n"
            f"Your Password Reset OTP is:\n"
            f"{otp}\n\n"
            f"This OTP is valid for 10 minutes. Please do not share this OTP with anyone.\n\n"
            f"If you did not request this, please ignore this email.\n\n"
            f"Best regards,\n"
            f"DR. DESIGN PVT. LTD. Team\n"
        )
    else:
        subject = "DR. DESIGN ERP - Your OTP Verification Code"
        headline = "Verify Your Email Address"
        sub_title = "Email Verification"
        intro_text = (
            "Thank you for registering on the DR. DESIGN ERP portal. "
            "Use the verification code below to complete your account registration:"
        )
        notice_text = (
            "Please do not share this OTP with anyone. If you did not attempt to register, "
            "you can safely disregard this email."
        )
        plain_message = (
            f"Hello,\n\n"
            f"Thank you for signing up with DR. DESIGN ERP.\n\n"
            f"Your One-Time Password (OTP) for account verification is:\n"
            f"{otp}\n\n"
            f"This OTP is valid for 10 minutes. Please do not share this OTP with anyone.\n\n"
            f"If you did not request this OTP, please ignore this email.\n\n"
            f"Best regards,\n"
            f"DR. DESIGN PVT. LTD. Team\n"
        )

    html_message = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #0f1217;
      color: #e2e8f0;
      margin: 0;
      padding: 24px;
    }}
    .email-card {{
      max-width: 520px;
      margin: 0 auto;
      background-color: #181d26;
      border-radius: 12px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 36px 32px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.4);
    }}
    .brand {{
      font-size: 20px;
      font-weight: 800;
      color: #ffffff;
      letter-spacing: 1px;
    }}
    .brand-sub {{
      font-size: 11px;
      font-weight: 700;
      color: #00bcd4;
      text-transform: uppercase;
      letter-spacing: 2px;
      margin-top: 4px;
    }}
    .title {{
      font-size: 18px;
      font-weight: 600;
      color: #ffffff;
      margin-top: 28px;
      margin-bottom: 8px;
    }}
    .desc {{
      font-size: 14px;
      color: #a0aec0;
      line-height: 1.6;
      margin-bottom: 20px;
    }}
    .otp-wrapper {{
      background: #0f1217;
      border: 2px dashed #00bcd4;
      border-radius: 10px;
      padding: 20px;
      text-align: center;
      margin: 28px 0;
    }}
    .otp-label {{
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 2px;
      color: #718096;
      margin-bottom: 6px;
    }}
    .otp-code {{
      font-size: 36px;
      font-weight: 800;
      letter-spacing: 8px;
      color: #00bcd4;
      font-family: 'Courier New', Courier, monospace;
    }}
    .otp-validity {{
      font-size: 12px;
      color: #a0aec0;
      margin-top: 8px;
    }}
    .security-notice {{
      font-size: 13px;
      color: #718096;
      line-height: 1.5;
      margin-top: 20px;
    }}
    .footer {{
      margin-top: 36px;
      border-top: 1px solid rgba(255, 255, 255, 0.08);
      padding-top: 18px;
      font-size: 12px;
      color: #718096;
      text-align: center;
    }}
  </style>
</head>
<body>
  <div class="email-card">
    <div class="brand">DR. DESIGN PVT. LTD.</div>
    <div class="brand-sub">ERP System &bull; {sub_title}</div>
    
    <div class="title">{headline}</div>
    <div class="desc">
      {intro_text}
    </div>

    <div class="otp-wrapper">
      <div class="otp-label">One-Time Password</div>
      <div class="otp-code">{otp}</div>
      <div class="otp-validity">⏱ Valid for 10 minutes only</div>
    </div>

    <div class="security-notice">
      {notice_text}
    </div>

    <div class="footer">
      &copy; 2026 DR. DESIGN PVT. LTD. All rights reserved.
    </div>
  </div>
</body>
</html>
"""

    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", settings.EMAIL_HOST_USER)

    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=from_email,
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )
        return True, None
    except Exception as exc:
        logger.error(f"Failed to send OTP to {email}: {str(exc)}", exc_info=True)
        return False, str(exc)


def generate_password_reset_token(email, otp_id):
    """
    Generates a cryptographically signed password reset token.
    """
    payload = f"{email.lower().strip()}:FORGOT_PASSWORD:{otp_id}"
    return signer.sign(payload)


def verify_password_reset_token(email, token, max_age=900):
    """
    Verifies a password reset token for the given email (valid for max_age seconds, default 15 min).
    Returns (True, None) or (False, error_message).
    """
    try:
        unsigned = signer.unsign(token, max_age=max_age)
        parts = unsigned.split(":")
        if len(parts) < 3:
            return False, "Invalid token format."
        signed_email, purpose, otp_id = parts[0], parts[1], parts[2]
        if signed_email.lower().strip() != email.lower().strip() or purpose != "FORGOT_PASSWORD":
            return False, "Reset token is not valid for this email address."
        return True, None
    except SignatureExpired:
        return False, "Password reset token has expired. Please request a new OTP."
    except BadSignature:
        return False, "Invalid or tampered password reset token."
    except Exception as e:
        return False, f"Token validation error: {str(e)}"
