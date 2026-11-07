# security_engine.py

import os
import io
import time
import secrets
import hashlib
import smtplib
import ssl
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from pypdf import PdfReader, PdfWriter

import config


class SecurityEngine:
    @staticmethod
    def hash_password(password: str, salt: str = None) -> tuple[str, str]:
        """Securely hashes passwords using SHA-256 with a unique salt."""
        if not salt:
            salt = secrets.token_hex(16)
        salted_password = salt + password
        hashed = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        return hashed, salt

    @staticmethod
    def verify_password(stored_hash: str, salt: str, password_attempt: str) -> bool:
        """Verifies the password attempt against the stored salt and hash."""
        hashed_attempt, _ = SecurityEngine.hash_password(password_attempt, salt)
        return secrets.compare_digest(stored_hash, hashed_attempt)

    @staticmethod
    def generate_otp() -> str:
        """Generates a cryptographically secure 6-digit OTP."""
        return f"{secrets.randbelow(900000) + 100000}"


class PDFStatementEngine:
    @staticmethod
    def generate_encrypted_statement(user_name: str, account_no: str, balance: float, transactions: list) -> io.BytesIO:
        """
        Generates an official electronic statement in PDF format 
        and encrypts it using the last 4 digits of the user's account number as the password.
        """
        raw_pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            raw_pdf_buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Bank Header
        title_style = ParagraphStyle(
            name="BankTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            alignment=1
        )
        elements.append(Paragraph(f"<b>{config.BANK_NAME}</b>", title_style))
        elements.append(Paragraph("<font size='10' color='#64748b'>Official Account Statement & Ledger</font>", ParagraphStyle(name="Sub", alignment=1, leading=14)))
        elements.append(Spacer(1, 15))
        
        # Account Metadata Table
        account_meta = [
            [f"Account Holder: {user_name}", f"Account No: {account_no}"],
            [f"Current Balance: PKR {balance:,.2f}", f"Generated On: {time.strftime('%Y-%m-%d %H:%M:%S')}"]
        ]
        meta_table = Table(account_meta, colWidths=[270, 270])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor("#1e293b")),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 20))
        
        # Transaction History Table Header
        table_data = [["Txn ID", "Type", "Counterparty", "Amount (PKR)", "Timestamp"]]
        for tx in transactions:
            table_data.append([
                tx.get("txn_id", "N/A")[:8],
                tx.get("type", "TRANSFER"),
                tx.get("counterparty", "N/A"),
                f"{tx.get('amount', 0.0):,.2f}",
                tx.get("timestamp", "N/A")
            ])
            
        if len(table_data) == 1:
            table_data.append(["-", "No recorded transactions found", "-", "-", "-"])
            
        txn_table = Table(table_data, colWidths=[80, 80, 150, 110, 120])
        txn_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        elements.append(txn_table)
        elements.append(Spacer(1, 30))
        note_text = "<font size='8' color='#94a3b8'>Confidential document. This electronic statement is password protected for your privacy. Do not share your banking password or PIN.</font>"
        elements.append(Paragraph(note_text, ParagraphStyle(name="Note", alignment=1)))
        
        # Build raw PDF in memory
        doc.build(elements)
        raw_pdf_buffer.seek(0)
        
        # Password Encryption Logic using pypdf
        reader = PdfReader(raw_pdf_buffer)
        writer = PdfWriter()
        
        for page in reader.pages:
            writer.add_page(page)
            
        # PDF password = Last 4 digits of the user's account number
        pdf_password = str(account_no)[-4:]
        writer.encrypt(user_password=pdf_password, owner_password=pdf_password)
        
        encrypted_pdf_buffer = io.BytesIO()
        writer.write(encrypted_pdf_buffer)
        encrypted_pdf_buffer.seek(0)
        
        return encrypted_pdf_buffer


class MailerService:
    @staticmethod
    def send_otp_email(recipient_email: str, otp_code: str) -> bool:
        """Sends an HTML formatted OTP verification email asynchronously with terminal debug fallback."""
        # Instant Console Debug Print (Taake delay hone par bhi terminal se OTP mil jaye)
        print("\n" + "="*50)
        print(f"🔥 [INSTANT OTP FOR {recipient_email}]: {otp_code}")
        print("="*50 + "\n")

        subject = f"{config.BANK_NAME} One-Time Login Verification Code"
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f1f5f9; padding: 25px;">
            <div style="max-width: 500px; margin: auto; background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                <h2 style="color: #0f172a; margin-top: 0;">{config.BANK_NAME}</h2>
                <p style="color: #475569; font-size: 15px;">A login request was initiated for your banking account.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <span style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #2563eb; background: #eff6ff; padding: 12px 24px; border-radius: 6px; border: 1px dashed #93c5fd;">
                        {otp_code}
                    </span>
                </div>
                <p style="color: #64748b; font-size: 13px;">This OTP is valid for <b>2 minutes</b>. If you did not initiate this request, contact support immediately.</p>
                <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;" />
                <p style="color: #94a3b8; font-size: 11px; text-align: center;">Automated Core Banking Security Dispatch</p>
            </div>
        </body>
        </html>
        """
        
        # Background Threading for Instant Response without blocking Flask server
        thread = threading.Thread(target=MailerService._send_mail, args=(recipient_email, subject, html_content))
        thread.start()
        return True

    @staticmethod
    def send_statement_email(recipient_email: str, account_no: str, pdf_buffer: io.BytesIO) -> bool:
        """Delivers the password-protected statement PDF attachment via email asynchronously."""
        subject = f"{config.BANK_NAME} Your Requested Account E-Statement"
        last_4 = str(account_no)[-4:]
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f1f5f9; padding: 25px;">
            <div style="max-width: 550px; margin: auto; background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                <h2 style="color: #0f172a; margin-top: 0;">{config.BANK_NAME}</h2>
                <p style="color: #334155; font-size: 15px;">Your requested official e-statement is attached with this email.</p>
                
                <div style="background-color: #f8fafc; border-left: 4px solid #2563eb; padding: 12px 16px; margin: 20px 0;">
                    <p style="margin: 0; color: #1e293b; font-weight: bold; font-size: 14px;">🔒 Password Protected Attachment</p>
                    <p style="margin: 4px 0 0 0; color: #475569; font-size: 13px;">
                        To open the PDF, enter the <b>last 4 digits of your account number</b>: <code>****{last_4}</code>
                    </p>
                </div>
                
                <p style="color: #64748b; font-size: 13px;">If you have any questions regarding these transactions, reach out via our 24/7 banking portal.</p>
                <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;" />
                <p style="color: #94a3b8; font-size: 11px; text-align: center;">Automated Core Banking Security Dispatch</p>
            </div>
        </body>
        </html>
        """
        
        thread = threading.Thread(
            target=MailerService._send_mail, 
            args=(recipient_email, subject, html_content, pdf_buffer, f"E-Statement_{account_no}.pdf")
        )
        thread.start()
        return True

    @staticmethod
    def _send_mail(recipient_email: str, subject: str, html_content: str, attachment_buffer: io.BytesIO = None, attachment_name: str = "") -> bool:
        """Internal SMTP TLS mail sender executed in background thread."""
        try:
            msg = MIMEMultipart()
            msg["From"] = f"{config.BANK_NAME} <{config.BANK_EMAIL}>"
            msg["To"] = recipient_email
            msg["Subject"] = subject
            
            msg.attach(MIMEText(html_content, "html"))
            
            if attachment_buffer and attachment_name:
                attachment_buffer.seek(0)
                part = MIMEBase("application", "pdf")
                part.set_payload(attachment_buffer.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{attachment_name}"'
                )
                msg.attach(part)
                
            context = ssl.create_default_context()
            with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT) as server:
                server.starttls(context=context)
                server.login(config.BANK_EMAIL, config.BANK_APP_PASSWORD)
                server.sendmail(config.BANK_EMAIL, recipient_email, msg.as_string())
                
            return True
        except Exception as e:
            print(f"[MAILER ERROR]: Failed to send email to {recipient_email}. Reason: {e}")
            return False