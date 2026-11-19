# Before/after security comparison

The demonstration is intentionally small and local. Run `python scripts\before_after_demo.py --enable-demo "' OR '1'='1"`. It creates only a temporary in-memory SQLite database containing synthetic rows and starts no web listener. Do not expose or adapt the unsafe query as an application feature.

| Vulnerability | Before state | Demonstrated impact | Applied protection | After state | Test evidence |
|---|---|---|---|---|---|
| SQL injection | Concatenated string in opt-in in-memory script | Synthetic query can return records beyond the intended username | `?` parameter binding in app queries | Payload treated as a literal value | `test_parameterized_query_preserves_input` passes |
| XSS | Raw script-like text as unsafe output would be executable if inserted as HTML | The demo prints escaped text, never renders it in a browser | Jinja autoescape; client `textContent`; CSP | Text remains text | `test_template_escapes_untrusted_text` passes |
| Request screening | No detector in isolated illustrative query | Demonstration input is separately evaluated by app detector in lab | Request middleware records and blocks detected examples | Matching request returns blocked response | `test_middleware_blocks_and_logs` and lab test pass |

The vulnerable SQL example is not a web endpoint and is disabled unless explicitly enabled. The displayed example does not represent a complete penetration test.
