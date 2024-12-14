import xrpl
import json
from xrpl.clients import JsonRpcClient
from xrpl.wallet import Wallet
from xrpl.transaction.main import autofill_and_sign, sign_and_submit
from xrpl.models.transactions import Payment, TrustSet
from xrpl.models.amounts import IssuedCurrencyAmount
import re
import time

# Connect to XRPL Testnet
client = JsonRpcClient("https://s.altnet.rippletest.net:51234/")

# Define Issuer and Recipient Details
ISSUER_SEED = "sIssuerSeedHere"  # Replace with your issuer's secret seed
RECIPIENT_SEED = "sRecipientSeedHere"  # Replace with your recipient's secret seed
TOKEN_NAME = "OSSECFeedToken"
TOKEN_SYMBOL = "OSEC"
CTI_FEED_FILE = "ossec_cti_feed.json"
CTI_FEED_URI = "https://example.com/ossec-feed.json"  # Replace with your hosted URI

# Function to Parse OSSEC Logs
def parse_ossec_logs(logs):
    indicators = []
    log_lines = logs.strip().split("\n")
    for line in log_lines:
        match_ip = re.search(r"Src IP: (\d+\.\d+\.\d+\.\d+)", line)
        match_user = re.search(r"User: (\S+)", line)
        match_rule = re.search(r"Rule: (\d+) .* -> '(.*?)'", line)

        if match_ip and match_rule:
            indicators.append({
                "type": "ip",
                "value": match_ip.group(1),
                "confidence": "high",
                "description": f"Rule {match_rule.group(1)}: {match_rule.group(2)}",
            })

        if match_user and match_rule:
            indicators.append({
                "type": "user",
                "value": match_user.group(1),
                "confidence": "medium",
                "description": f"Rule {match_rule.group(1)}: {match_rule.group(2)}",
            })

    return indicators

# Example OSSEC Log Input
ossec_logs = """
** Alert 1589724900.12: - syslog,authentication_failures 
2024 Dec 14 12:34:56 hostname->/var/log/secure
Rule: 1002 (level 5) -> 'Failed SSH login.'
Src IP: 192.168.1.100
User: root
"""

# Parse Logs and Generate CTI Feed
indicators = parse_ossec_logs(ossec_logs)
cti_feed = {
    "token": {
        "name": TOKEN_NAME,
        "symbol": TOKEN_SYMBOL,
        "issuer": None,  # To be updated after wallet creation
        "description": "Tokenized representation of OSSEC logs for threat intelligence.",
        "version": "1.0"
    },
    "cti_feed": {
        "feed_id": "ossec-feed-001",
        "feed_name": "OSSEC Threat Feed",
        "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "indicators": indicators
    }
}

# Save CTI Feed JSON
with open(CTI_FEED_FILE, "w") as f:
    json.dump(cti_feed, f, indent=4)

# Issuer and Recipient Wallets
issuer_wallet = Wallet(seed=ISSUER_SEED)
recipient_wallet = Wallet(seed=RECIPIENT_SEED)
cti_feed["token"]["issuer"] = issuer_wallet.classic_address

# 1. Create Trustline for the Recipient
def create_trustline(recipient_wallet, issuer_wallet, token_symbol, limit):
    trust_set_tx = TrustSet(
        account=recipient_wallet.classic_address,
        limit_amount=IssuedCurrencyAmount(
            currency=token_symbol,
            value=limit,
            issuer=issuer_wallet.classic_address,
        ),
    )
    signed_tx = autofill_and_sign(trust_set_tx, recipient_wallet, client)
    response = sign_and_submit(signed_tx, client)
    print("Trustline Created:", response.result)

create_trustline(recipient_wallet, issuer_wallet, TOKEN_SYMBOL, "1000")  # Limit of 1000 tokens

# 2. Issue Token to the Recipient
def issue_token(issuer_wallet, recipient_wallet, token_symbol, amount):
    payment_tx = Payment(
        account=issuer_wallet.classic_address,
        destination=recipient_wallet.classic_address,
        amount=IssuedCurrencyAmount(
            currency=token_symbol,
            value=amount,
            issuer=issuer_wallet.classic_address,
        ),
        memos=[
            {
                "Memo": {
                    "MemoType": "OSSEC_FEED_URI",
                    "MemoData": xrpl.utils.str_to_hex(CTI_FEED_URI),
                }
            }
        ]
    )
    signed_tx = autofill_and_sign(payment_tx, issuer_wallet, client)
    response = sign_and_submit(signed_tx, client)
    print("Token Issued:", response.result)

issue_token(issuer_wallet, recipient_wallet, TOKEN_SYMBOL, "1")  # Issue 1 token

# 3. Transfer Token to Another Address (Optional)
def transfer_token(sender_wallet, recipient_address, token_symbol, issuer_address, amount):
    payment_tx = Payment(
        account=sender_wallet.classic_address,
        destination=recipient_address,
        amount=IssuedCurrencyAmount(
            currency=token_symbol,
            value=amount,
            issuer=issuer_address,
        )
    )
    signed_tx = autofill_and_sign(payment_tx, sender_wallet, client)
    response = sign_and_submit(signed_tx, client)
    print("Token Transferred:", response.result)

# Uncomment to transfer tokens further
# transfer_token(recipient_wallet, "rAnotherRecipientAddressHere", TOKEN_SYMBOL, issuer_wallet.classic_address, "1")
