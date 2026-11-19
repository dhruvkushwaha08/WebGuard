import re
USERNAME_RE = re.compile(r"^[\w.-]{3,32}$", re.UNICODE)
EMAIL_RE = re.compile(r"^[^\s@]{1,64}@[^\s@.]+(?:\.[^\s@.]+)+$")

def validate_username(value):
    if not isinstance(value, str) or not USERNAME_RE.fullmatch(value):
        return False, "Username must be 3–32 characters using letters, numbers, dot, underscore, or hyphen."
    return True, ""

def validate_email(value):
    if not isinstance(value, str) or len(value) > 254 or not EMAIL_RE.fullmatch(value):
        return False, "Enter a valid email address."
    return True, ""

def validate_password(value):
    if not isinstance(value, str) or not 10 <= len(value) <= 128:
        return False, "Password must be between 10 and 128 characters."
    if not any(c.isalpha() for c in value) or not any(c.isdigit() for c in value):
        return False, "Password must include at least one letter and one number."
    return True, ""

def validate_text(value, max_length=500):
    if not isinstance(value, str): return False, "Text input must be a string."
    if len(value) > max_length: return False, f"Text must be at most {max_length} characters."
    return True, ""
