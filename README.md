# 🔐 Cryptographically-Enforced-Dynamic-Access-Control-in-the-Cloud

A secure file storage and sharing system using Shamir's Secret Sharing (SSS), AES encryption, and RSA key wrapping.

## 🎯 Project Overview

This application provides a secure file upload and download system with the following features:

- **🔐 Shamir's Secret Sharing**: Split secret into multiple shares
- **🔒 AES Encryption**: Files are encrypted before storage
- **🔑 RSA Key Wrapping**: AES keys are securely wrapped for each user
- **📧 Email Notifications**: Share keys are automatically sent via email
- **👥 Role-Based Access**: Different permissions for ADMIN, MANAGER, EMPLOYEE
- **☁️ Cloud Storage**: Files stored in AWS S3

## 🔧 Technology Stack

### Backend
- **Flask**: Web framework
- **Shamir's Secret Sharing**: Secret splitting and reconstruction
- **AES-256**: File encryption
- **RSA-2048**: Key wrapping/unwrapping
- **AWS S3**: Cloud file storage
- **JWT**: Authentication tokens
- **SMTP**: Email notifications

### Frontend
- **HTML5/CSS3**: Modern floating card UI
- **JavaScript**: Form validation and AJAX requests
- **Bootstrap**: Responsive design components

## 🚀 Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

### Environment Setup
1. Configure AWS credentials in `.env` file
2. Set up email credentials in `appv4.py`
3. Ensure user database exists in `user_database/`

### Run Application
```bash
python appv4.py
```

Access at: `http://127.0.0.1:5000`

## 📝 Step-by-Step Guide

### 1. User Registration & Login

#### Registration
1. Navigate to `/register`
2. Fill in registration form:
   - First Name
   - Last Name  
   - Email
   - Password
   - Role (ADMIN/MANAGER/EMPLOYEE)
3. Submit form
4. Account created with ACTIVE status

#### Login
1. Navigate to `/` (home page)
2. Enter credentials:
   - Username: `{first_name}_{last_name}`
   - Password
3. System validates credentials and assigns JWT token
4. Redirected to dashboard based on role

### 2. File Upload Process (ADMIN/MANAGER only)

#### Step 1: Access Upload Page
1. Login as ADMIN or MANAGER
2. Navigate to `/upload`
3. Fill upload form:
   - **Select File**: Choose file to upload
   - **Enter Secret**: Create a secret phrase
   - **Set Threshold**: Number of shares required (2-6)

#### Step 2: Backend Processing
1. **File Encryption**:
   ```python
   # AES-256 encryption
   aes_key = generate_aes_key()
   encrypted_data = aes_encrypt(file_content, aes_key)
   ```

2. **Cloud Storage**:
   ```python
   # Upload to S3
   s3.put_object(Bucket=S3_BUCKET_NAME, Key=filename, Body=encrypted_data)
   ```

3. **Key Wrapping**:
   ```python
   # RSA wrap AES key for each employee
   for employee in employees:
       wrapped_key = rsa_wrap_key(aes_key, employee_public_key)
       save_wrapped_key(filename, employee_email, wrapped_key)
   ```

4. **Secret Sharing**:
   ```python
   # Convert secret to numeric
   secret_numeric = sum(ord(c) for c in secret_phrase)
   
   # Generate shares using Shamir's Secret Sharing
   shares = generate_shares(secret_numeric, num_employees, threshold)
   
   # Send shares via email
   for i, employee in enumerate(employees):
       send_share_email(employee.email, shares[i])
   ```

#### Step 3: Share Distribution
1. **Email Notifications**: Each employee receives their unique share
2. **Share Tracking**: System logs which share went to which email
3. **Console Output**: Shows all generated shares for reference

### 3. File Download Process (All Roles)

#### Step 1: Access File List
1. Navigate to `/list-files`
2. View all uploaded files (most recent first)
3. See threshold requirements for each file

#### Step 2: Collect Shares
1. Click "Download" button for desired file
2. Enter required number of shares (based on threshold)
3. **Order-Independent**: Shares can be entered in any order
4. Submit form

#### Step 3: Backend Validation
1. **Share Collection**: System collects all provided shares
2. **Share Validation**: Matches against tracking database
3. **Secret Reconstruction**:
   ```python
   # Reconstruct using Shamir's algorithm
   reconstructed_secret = reconstruct_secret(collected_shares)
   
   # Validate against stored secret
   if reconstructed_secret == stored_secret:
       # Proceed to file decryption
   ```

4. **File Decryption**:
   ```python
   # RSA unwrap AES key
   aes_key = rsa_unwrap_key(wrapped_key, user_private_key)
   
   # AES decrypt file
   decrypted_content = aes_decrypt(encrypted_file, aes_key)
   ```

5. **Download**: File downloads to user's device

### 4. Project & Company Information

#### Access Protected Pages
1. Navigate to dashboard
2. Select information type:
   - **Project Details**: Secure project information
   - **Company Details**: Secure company information  
   - **Employee Details** (ADMIN only): User management

#### Security Middleware
- All protected routes require JWT authentication
- Role-based access control enforced
- Session management for security

## 👥 User Roles & Permissions

### ADMIN
- ✅ Upload files
- ✅ Download files
- ✅ View all protected pages
- ✅ Manage employee details
- ✅ Full system access

### MANAGER  
- ✅ Upload files
- ✅ Download files
- ✅ View project/company details
- ❌ Cannot access employee management

### EMPLOYEE
- ❌ Cannot upload files
- ✅ Download files (with valid shares)
- ✅ View project/company details
- ❌ Cannot access employee management

## 📁 File Structure

```
app199v4/
├── appv4.py                 # Main Flask application
├── requirements.txt           # Python dependencies
├── .env                    # Environment variables
├── templates/               # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── upload_page.html
│   ├── file_list.html
│   └── details.html
├── static/                 # Static assets
│   └── cloud-security-and-principles.jpg
├── user_database/          # User credentials
│   └── user_credentials.json
├── rsa_keys/              # RSA key pairs
│   ├── user1@gmail.com_public.pem
│   └── user1@gmail.com_private.pem
├── wrapped_keys/           # RSA-wrapped AES keys
├── secrets.txt            # Stored file secrets
├── share_tracking.txt      # Share distribution logs
├── email_notifications.py   # Email sending logic
├── secret_sharing.py      # SSS implementation
├── reconstruct_secret.py   # Secret reconstruction
├── crypto_utils.py        # Cryptographic utilities
└── README.md              # This file
```

## 🛠️ Configuration

### Environment Variables (.env)
```bash
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
S3_BUCKET_NAME=your_bucket_name
AWS_REGION=your_region
```

### Email Configuration (appv4.py)
```python
sender_email = "your_email@gmail.com"
sender_password = "your_app_password"
```

### User Database Format
```json
{
  "cred": [
    {
      "user_id": "first_last",
      "first name": "first",
      "last name": "last", 
      "email": "user@example.com",
      "role": "ADMIN|MANAGER|EMPLOYEE",
      "password": "hashed_password",
      "status": "ACTIVE"
    }
  ]
}
```

## 🔧 Troubleshooting

### Common Issues & Solutions

#### Upload Issues
- **"Upload failed"**: Check AWS credentials and S3 bucket permissions
- **Email not sending**: Verify SMTP settings and app passwords
- **Share generation errors**: Check secret_sharing.py implementation

#### Download Issues  
- **"Invalid shares"**: Ensure correct number of shares entered
- **Order problems**: System now supports any order of shares
- **Secret validation failed**: Check share_tracking.txt for correct values

#### Login Issues
- **"Invalid credentials"**: Verify username format (first_last)
- **Role assignment errors**: Check user_credentials.json format
- **Session issues**: Clear browser cookies and retry

#### Debug Mode
Enable debug mode for detailed logging:
```python
app.run(debug=True)
```

Console will show:
- Share generation and distribution
- Secret reconstruction process
- File encryption/decryption steps
- Authentication and authorization checks

### Support Files Generated
- `secrets.txt`: Stores file secrets and thresholds
- `share_tracking.txt`: Logs share distribution with timestamps
- RSA key pairs in `rsa_keys/` directory
- Wrapped AES keys in `wrapped_keys/` directory

---

## 🚀 Getting Started

1. **Clone/Download** the project
2. **Install dependencies**: `pip install -r requirements.txt`
3. **Configure environment**: Set up `.env` and email settings
4. **Create users**: Add accounts via registration page
5. **Start application**: `python appv4.py`
6. **Access system**: Open `http://127.0.0.1:5000`

For detailed setup instructions or troubleshooting, refer to the sections above.

---

**🔐 Secure File Sharing with Shamir's Secret Sharing**  
*Built with Flask, AES, RSA, and AWS S3*
