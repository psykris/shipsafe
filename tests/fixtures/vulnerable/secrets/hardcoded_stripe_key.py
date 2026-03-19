# Intentionally vulnerable: hardcoded Stripe secret key
import stripe
stripe.api_key = "sk_live_FakeStripeKeyForShipSafeTestSuite000"  # test fixture
