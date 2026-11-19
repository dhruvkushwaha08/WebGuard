from app.security.detector import inspect_value

def test_xss_payloads_detected():
    for payload in ["<script>alert(1)</script>","<img src=x onerror=alert(1)>","<svg onload=alert(1)>","javascript:alert(1)"]:
        assert any(f["attack_type"]=="XSS" for f in inspect_value(payload))

def test_xss_documentation_text_is_not_misclassified():
    for text in ["The <script> tag is discussed in the security guide.", "The onerror= attribute is unsafe.", "javascript: is a dangerous URL scheme."]:
        assert not any(f["attack_type"]=="XSS" for f in inspect_value(text)), text

def test_template_escapes_untrusted_text(app):
    with app.test_request_context("/"):
        from flask import render_template_string
        rendered=render_template_string("{{ user_text }}",user_text="<script>alert(1)</script>")
        assert "&lt;script&gt;" in rendered
        assert "<script>" not in rendered
