# 🔐 Password Manager with Encryption

A secure password manager that stores credentials using AES encryption and protects access with a master password.

## 🚀 Features

- Master password authentication
- AES-encrypted password storage
- Add credentials
- View credentials
- Update credentials
- Delete credentials
- Generate strong random passwords
- Secure local storage

## 🛠️ Technologies Used

- Python 3
- cryptography library
- JSON

## 📂 Project Structure

```text
password-manager/
│
├── main.py
├── vault.json
└── README.md
```

## 📦 Installation

Install required dependencies:

```bash
pip install cryptography
```

## ▶️ How to Run

```bash
python main.py
```

## 🔒 Security Notes

- Passwords are encrypted before storage
- The master password is never stored in plain text
- Uses industry-standard AES encryption
- Encryption keys are generated securely

## 📈 Future Improvements

- Clipboard auto-copy
- Password strength checker
- Two-factor authentication (2FA)
- GUI application
- Cloud backup support
