"""Email notification sender for scan completion."""

import os
import logging
import requests
from typing import Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class EmailSender:
    """Send email notifications for scan completion using Resend (same as DarkAI-consolidated)."""
    
    def __init__(self):
        """Initialize email sender with configuration from environment variables."""
        # Resend API (primary method, same as DarkAI-consolidated)
        self.resend_api_key = os.getenv('RESEND_API_KEY', '')
        self.from_email = os.getenv('FROM_EMAIL', 'onboarding@resend.dev')  # Default Resend domain
        self.from_name = os.getenv('FROM_NAME', 'DarkOrca')
        self.base_url = os.getenv('BASE_URL', 'http://localhost:5001')
        
        # Fallback to SMTP if Resend not configured
        self.smtp_server = os.getenv('SMTP_SERVER', '')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_username = os.getenv('SMTP_USERNAME', '')
        self.smtp_password = os.getenv('SMTP_PASSWORD', '')
        
        # Determine which method to use
        if self.resend_api_key:
            self.method = 'resend'
            self.enabled = True
            logger.info(f"Email notifications enabled via Resend (from: {self.from_email})")
        elif self.smtp_username and self.smtp_password:
            self.method = 'smtp'
            self.enabled = True
            logger.info(f"Email notifications enabled via SMTP (server: {self.smtp_server})")
        else:
            self.method = None
            self.enabled = False
            logger.warning("Email notifications disabled: RESEND_API_KEY or SMTP credentials not configured")
    
    def is_enabled(self) -> bool:
        """Check if email notifications are enabled."""
        return self.enabled
    
    def send_scan_complete_notification(
        self,
        to_email: str,
        target_url: str,
        scan_mode: str,
        risk_score: float,
        risk_level: str,
        findings_count: int,
        shareable_id: Optional[str] = None,
        scan_id: Optional[str] = None
    ) -> bool:
        """
        Send email notification when scan completes.
        
        Args:
            to_email: Recipient email address
            target_url: Scanned target URL
            scan_mode: Scan mode (defensive, offensive, comprehensive)
            risk_score: Overall risk score
            risk_level: Risk level (critical, high, medium, low, minimal)
            findings_count: Number of findings
            shareable_id: Shareable results ID (preferred)
            scan_id: Regular scan ID (fallback)
            
        Returns:
            True if email sent successfully, False otherwise
        """
        if not self.enabled:
            logger.warning("Email notifications disabled, skipping email send")
            return False
        
        try:
            # Determine results URL
            if shareable_id:
                results_url = urljoin(self.base_url, f"/results/{shareable_id}")
            elif scan_id:
                results_url = urljoin(self.base_url, f"/?scan_id={scan_id}")
            else:
                results_url = self.base_url
            
            # Risk level emoji and colors (matching DarkAI theme)
            risk_config = {
                'critical': {'emoji': '🔴', 'color': '#ff6b6b', 'bg': 'rgba(255, 107, 107, 0.18)', 'border': 'rgba(255, 107, 107, 0.3)'},
                'high': {'emoji': '🟠', 'color': '#ff8c42', 'bg': 'rgba(255, 140, 66, 0.18)', 'border': 'rgba(255, 140, 66, 0.3)'},
                'medium': {'emoji': '🟡', 'color': '#fde047', 'bg': 'rgba(253, 224, 71, 0.18)', 'border': 'rgba(253, 224, 71, 0.3)'},
                'low': {'emoji': '🟢', 'color': '#93c5fd', 'bg': 'rgba(147, 197, 253, 0.18)', 'border': 'rgba(147, 197, 253, 0.3)'},
                'minimal': {'emoji': '⚪', 'color': '#d1d5db', 'bg': 'rgba(209, 213, 219, 0.18)', 'border': 'rgba(209, 213, 219, 0.3)'},
            }
            risk_info = risk_config.get(risk_level.lower(), risk_config['minimal'])
            
            # Plain text version
            text = f"""DarkOrca - Scan Complete

Your security scan has completed.

Target: {target_url}
Scan Mode: {risk_info['emoji']} {scan_mode.title()}
Risk Score: {risk_score:.1f}/100
Risk Level: {risk_level.upper()}
Findings: {findings_count}

View Results:
{results_url}

---
DarkOrca - Automated Security Assessment Tool
Part of Dark AI - https://darkai.ca/
"""
            
            # HTML version - Email-client compatible with inline styles
            # Updated to match DarkOrca branding with dark theme
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #05060b; line-height: 1.6;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #05060b; background: radial-gradient(circle at top, #141825 0, #020308 60%);">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; background-color: #111827; border-radius: 12px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.45);">
                    <!-- Header -->
                    <tr>
                        <td style="background-color: #111827; padding: 40px 30px 30px 30px; text-align: center; border-radius: 12px 12px 0 0;">
                            <img src="{self.base_url}/static/DarkOrca.png" alt="DarkOrca" style="max-height: 80px; width: auto; margin-bottom: 15px; display: block; margin-left: auto; margin-right: auto;" />
                            <h1 style="margin: 15px 0 0 0; color: #f2f3f5; font-size: 28px; font-weight: 700; letter-spacing: -0.01em;">
                                Scan Complete
                            </h1>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 30px 30px; background-color: #111827;">
                            <p style="margin: 0 0 20px 0; color: #f2f3f5; font-size: 16px;">
                                Your security scan has completed successfully.
                            </p>
                            
                            <!-- Info Card -->
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #0b0d16; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; margin: 20px 0;">
                                <tr>
                                    <td style="padding: 24px;">
                                        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                            <tr>
                                                <td style="padding: 12px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.08);">
                                                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                                        <tr>
                                                            <td style="color: #9aa0a6; font-size: 14px; font-weight: 500;">Target:</td>
                                                            <td align="right" style="color: #f2f3f5; font-size: 14px; font-weight: 600;">
                                                                <a href="{target_url}" style="color: #ff6b6b; text-decoration: none;">{target_url}</a>
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 12px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.08);">
                                                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                                        <tr>
                                                            <td style="color: #9aa0a6; font-size: 14px; font-weight: 500;">Scan Mode:</td>
                                                            <td align="right" style="color: #f2f3f5; font-size: 14px; font-weight: 600;">
                                                                {risk_info['emoji']} {scan_mode.title()}
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 12px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.08);">
                                                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                                        <tr>
                                                            <td style="color: #9aa0a6; font-size: 14px; font-weight: 500;">Risk Score:</td>
                                                            <td align="right" style="color: #f2f3f5; font-size: 14px; font-weight: 600;">{risk_score:.1f}/100</td>
                                                        </tr>
                                                    </table>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 12px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.08);">
                                                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                                        <tr>
                                                            <td style="color: #9aa0a6; font-size: 14px; font-weight: 500;">Risk Level:</td>
                                                            <td align="right">
                                                                <span style="display: inline-block; padding: 6px 14px; background-color: {risk_info['bg']}; color: {risk_info['color']}; border: 1px solid {risk_info['border']}; border-radius: 12px; font-weight: 600; font-size: 12px;">
                                                                    {risk_level.upper()}
                                                                </span>
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="padding: 12px 0;">
                                                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                                        <tr>
                                                            <td style="color: #9aa0a6; font-size: 14px; font-weight: 500;">Findings:</td>
                                                            <td align="right" style="color: #f2f3f5; font-size: 14px; font-weight: 600;">{findings_count}</td>
                                                        </tr>
                                                    </table>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- Button -->
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                <tr>
                                    <td align="center" style="padding: 24px 0;">
                                        <a href="{results_url}" style="display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #ff6b6b, #c43434); color: #ffffff; text-decoration: none; border-radius: 999px; font-weight: 600; font-size: 16px; box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3);">
                                            View Full Results
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            
                            <p style="margin: 20px 0 0 0; text-align: center; color: #9aa0a6; font-size: 12px;">
                                This link will remain active for 30 days. You can share it with others or download a PDF report.
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #0b0d16; padding: 24px 30px; text-align: center; border-top: 1px solid rgba(255, 255, 255, 0.08); border-radius: 0 0 12px 12px;">
                            <p style="margin: 0 0 8px 0; color: #f2f3f5; font-size: 16px; font-weight: 700;">
                                DarkOrca
                            </p>
                            <p style="margin: 0 0 8px 0; color: #9aa0a6; font-size: 13px;">
                                Automated Security Assessment Tool
                            </p>
                            <p style="margin: 8px 0 0 0; color: #6b7280; font-size: 12px;">
                                Part of <a href="https://darkai.ca/" style="color: #ff6b6b; text-decoration: none; font-weight: 600;">Dark AI</a>
                            </p>
                            <p style="margin: 12px 0 0 0; color: #6b7280; font-size: 11px;">
                                This is an automated notification. Please do not reply to this email.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
            
            # Send via Resend (preferred, same as DarkAI-consolidated) or SMTP (fallback)
            if self.method == 'resend':
                return self._send_via_resend(to_email, f'DarkOrca Complete: {target_url} - {risk_level.upper()} Risk', text, html)
            elif self.method == 'smtp':
                return self._send_via_smtp(to_email, f'DarkOrca Complete: {target_url} - {risk_level.upper()} Risk', text, html)
            else:
                logger.error("No email method configured")
                return False
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}", exc_info=True)
            return False
    
    def _send_via_resend(self, to_email: str, subject: str, text: str, html: str) -> bool:
        """Send email via Resend API (same as DarkAI-consolidated)."""
        try:
            headers = {
                'Authorization': f'Bearer {self.resend_api_key}',
                'Content-Type': 'application/json',
            }
            
            payload = {
                'from': f'{self.from_name} <{self.from_email}>',
                'to': [to_email],
                'subject': subject,
                'html': html,
                'text': text,
            }
            
            logger.info(f"Attempting to send email via Resend: from={self.from_email}, to={to_email}, subject={subject}")
            
            response = requests.post(
                'https://api.resend.com/emails',
                headers=headers,
                json=payload,
                timeout=10
            )
            
            logger.info(f"Resend API response: status={response.status_code}, body={response.text[:200]}")
            
            if response.status_code == 200:
                response_data = response.json() if response.text else {}
                email_id = response_data.get('id', 'unknown')
                logger.info(f"Email sent successfully via Resend to {to_email} (email_id: {email_id})")
                return True
            else:
                # Log full error details
                try:
                    error_data = response.json()
                    error_message = error_data.get('message', response.text)
                    logger.error(f"Resend API error {response.status_code}: {error_message}")
                    if 'message' in error_data:
                        logger.error(f"Full error details: {error_data}")
                except:
                    logger.error(f"Resend API error {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Resend API request failed: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Resend send failed: {e}", exc_info=True)
            return False
    
    def _send_via_smtp(self, to_email: str, subject: str, text: str, html: str) -> bool:
        """Send email via SMTP (fallback)."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f'{self.from_name} <{self.from_email}>'
            msg['To'] = to_email
            
            part1 = MIMEText(text, 'plain')
            part2 = MIMEText(html, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email sent via SMTP to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"SMTP send failed: {e}", exc_info=True)
            return False
    
    def send_welcome_email(self, to_email: str, username: str) -> bool:
        """
        Send welcome email to newly registered user.
        
        Args:
            to_email: Recipient email address
            username: Username of the new user
            
        Returns:
            True if email sent successfully, False otherwise
        """
        if not self.enabled:
            logger.warning("Email notifications disabled, skipping welcome email")
            return False
        
        try:
            # Plain text version
            text = f"""Welcome to DarkOrca!

Hi {username},

Thank you for registering with DarkOrca! Your account has been successfully created.

You can now:
- Run security scans on targets
- Save and manage scan results
- Receive email notifications when scans complete

Get started by visiting:
{self.base_url}

---

DarkOrca - Automated Security Assessment Tool
Part of Dark AI - https://darkai.ca/
"""
            
            # HTML version - matching DarkOrca branding
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #05060b; line-height: 1.6;">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #05060b; background: radial-gradient(circle at top, #141825 0, #020308 60%);">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; background-color: #111827; border-radius: 12px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.45);">
                    <!-- Header -->
                    <tr>
                        <td style="background-color: #111827; padding: 40px 30px 30px 30px; text-align: center; border-radius: 12px 12px 0 0;">
                            <img src="{self.base_url}/static/DarkOrca.png" alt="DarkOrca" style="max-height: 80px; width: auto; margin-bottom: 15px; display: block; margin-left: auto; margin-right: auto;" />
                            <h1 style="margin: 15px 0 0 0; color: #f2f3f5; font-size: 28px; font-weight: 700; letter-spacing: -0.01em;">
                                Welcome to DarkOrca!
                            </h1>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 30px 30px; background-color: #111827;">
                            <p style="margin: 0 0 20px 0; color: #f2f3f5; font-size: 16px;">
                                Hi <strong style="color: #ff6b6b;">{username}</strong>,
                            </p>
                            
                            <p style="margin: 0 0 20px 0; color: #f2f3f5; font-size: 16px; line-height: 1.8;">
                                Thank you for registering with DarkOrca! Your account has been successfully created.
                            </p>
                            
                            <!-- Info Card -->
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #0b0d16; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; margin: 24px 0;">
                                <tr>
                                    <td style="padding: 24px;">
                                        <p style="margin: 0 0 16px 0; color: #9aa0a6; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">
                                            Get Started
                                        </p>
                                        <p style="margin: 0 0 12px 0; color: #f2f3f5; font-size: 15px;">
                                            You can now:
                                        </p>
                                        <ul style="margin: 0; padding-left: 20px; color: #f2f3f5; font-size: 15px; line-height: 2;">
                                            <li style="margin-bottom: 8px;">Run security scans on targets</li>
                                            <li style="margin-bottom: 8px;">Save and manage scan results</li>
                                            <li style="margin-bottom: 8px;">Receive email notifications when scans complete</li>
                                        </ul>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- Button -->
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                <tr>
                                    <td align="center" style="padding: 24px 0;">
                                        <a href="{self.base_url}" style="display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #ff6b6b, #c43434); color: #ffffff; text-decoration: none; border-radius: 999px; font-weight: 600; font-size: 16px; box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3);">
                                            Get Started
                                        </a>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #0b0d16; padding: 24px 30px; text-align: center; border-top: 1px solid rgba(255, 255, 255, 0.08); border-radius: 0 0 12px 12px;">
                            <p style="margin: 0 0 8px 0; color: #f2f3f5; font-size: 16px; font-weight: 700;">
                                DarkOrca
                            </p>
                            <p style="margin: 0 0 8px 0; color: #9aa0a6; font-size: 13px;">
                                Automated Security Assessment Tool
                            </p>
                            <p style="margin: 8px 0 0 0; color: #6b7280; font-size: 12px;">
                                Part of <a href="https://darkai.ca/" style="color: #ff6b6b; text-decoration: none; font-weight: 600;">Dark AI</a>
                            </p>
                            <p style="margin: 12px 0 0 0; color: #6b7280; font-size: 11px;">
                                This is an automated notification. Please do not reply to this email.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
            
            # Send via Resend (preferred) or SMTP (fallback)
            if self.method == 'resend':
                return self._send_via_resend(to_email, 'Welcome to DarkOrca!', text, html)
            elif self.method == 'smtp':
                return self._send_via_smtp(to_email, 'Welcome to DarkOrca!', text, html)
            else:
                logger.error("No email method configured")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send welcome email: {e}", exc_info=True)
            return False


# Global instance
_email_sender = None


def get_email_sender() -> EmailSender:
    """Get or create the global email sender instance."""
    global _email_sender
    if _email_sender is None:
        _email_sender = EmailSender()
    return _email_sender

