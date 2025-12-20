#!/usr/bin/env python3
"""Test email sending functionality."""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from src.utils.email_sender import get_email_sender

def test_email():
    """Test email sending."""
    print("=" * 60)
    print("Email Configuration Test")
    print("=" * 60)
    
    # Check environment variables
    resend_key = os.getenv('RESEND_API_KEY', '')
    from_email = os.getenv('FROM_EMAIL', 'onboarding@resend.dev')
    smtp_user = os.getenv('SMTP_USERNAME', '')
    
    print(f"\n1. Environment Variables:")
    print(f"   RESEND_API_KEY: {'SET' if resend_key else 'NOT SET'}")
    if resend_key:
        print(f"   RESEND_API_KEY (first 10 chars): {resend_key[:10]}...")
    print(f"   FROM_EMAIL: {from_email}")
    print(f"   SMTP_USERNAME: {'SET' if smtp_user else 'NOT SET'}")
    
    # Get email sender
    print(f"\n2. Email Sender Status:")
    email_sender = get_email_sender()
    print(f"   Enabled: {email_sender.is_enabled()}")
    print(f"   Method: {email_sender.method}")
    print(f"   From Email: {email_sender.from_email}")
    print(f"   From Name: {email_sender.from_name}")
    
    if not email_sender.is_enabled():
        print("\n❌ Email notifications are DISABLED!")
        print("   Please check your .env file and ensure RESEND_API_KEY is set.")
        return False
    
    # Test email sending
    print(f"\n3. Testing Email Send:")
    test_email = input("   Enter test email address (or press Enter to skip): ").strip()
    
    if not test_email:
        print("   Skipping email send test.")
        return True
    
    print(f"   Sending test email to {test_email}...")
    
    success = email_sender.send_scan_complete_notification(
        to_email=test_email,
        target_url="https://example.com",
        scan_mode="defensive",
        risk_score=50.0,
        risk_level="high",
        findings_count=5,
        shareable_id="test123",
        scan_id="test_scan_123"
    )
    
    if success:
        print(f"   ✅ Email sent successfully!")
        print(f"   Check your inbox (and spam folder) for the email.")
    else:
        print(f"   ❌ Email send failed!")
        print(f"   Check the server logs above for error details.")
    
    return success

if __name__ == "__main__":
    try:
        test_email()
    except KeyboardInterrupt:
        print("\n\nTest cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
