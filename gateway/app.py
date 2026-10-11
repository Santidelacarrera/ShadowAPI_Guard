"""Demo target behind the simulation probe and the WAF: capture -> waf -> app."""
from capture import CaptureMiddleware
from demo_app import app as demo
from waf import WafMiddleware

app = CaptureMiddleware(WafMiddleware(demo))
