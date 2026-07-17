# email_notifications.py

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(subject, body, recipient_email, sender_email, sender_password):
    """
    Function to send an email notification.
    
    :param subject: Subject of the email
    :param body: Body of the email
    :param recipient_email: Recipient's email address
    :param sender_email: Sender's email address
    :param sender_password: Sender's email password (for Gmail SMTP, use app-specific password)
    """
    port = 465  # SSL port
    smtp_server = "smtp.gmail.com"
    
    # Create the email message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))
    
    # Secure the connection and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())

def notify_share_generated(recipient_email, sender_email, sender_password, share_info):
    """
    Send notification when an individual share is generated.
    """
    # Parse share tuple to extract just the share value
    if isinstance(share_info, str) and share_info.startswith('(') and share_info.endswith(')'):
        # Extract second element from tuple string like "(2, 1096)"
        share_value = share_info.split(', ')[1].strip(')')
        # Send the exact share value (no padding)
        share_pin = share_value
    else:
        # Fallback to original format if parsing fails
        share_pin = str(share_info)
    
    subject = "Your Share Generated"
    body = f"Hello,\n\nHere is your share: {share_pin}\n\nBest regards,\nShamir's Secret Sharing System"
    send_email(subject, body, recipient_email, sender_email, sender_password)

def notify_secret_reconstructed(recipient_email, sender_email, sender_password, secret):
    """
    Send notification when the secret is successfully reconstructed.
    """
    subject = "Secret Successfully Reconstructed"
    body = f"The secret has been successfully reconstructed: {secret}"
    send_email(subject, body, recipient_email, sender_email, sender_password)
