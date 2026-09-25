import hashlib
import os
from pathlib import Path

from solcx import compile_source, set_solc_version
from web3 import Web3


# ============================================================
# GANACHE CONNECTION
# ============================================================

GANACHE_URL = os.getenv(
    "GANACHE_URL",
    "http://127.0.0.1:8545"
)

w3 = Web3(
    Web3.HTTPProvider(GANACHE_URL)
)


# ============================================================
# CHECK BLOCKCHAIN CONNECTION
# ============================================================

def is_blockchain_connected() -> bool:
    return w3.is_connected()


# ============================================================
# SHA-256 EVIDENCE HASH
# ============================================================

def generate_evidence_hash(evidence: str) -> str:
    return hashlib.sha256(
        evidence.encode("utf-8")
    ).hexdigest()


# ============================================================
# COMPILE SMART CONTRACT
# ============================================================

def compile_contract():
    set_solc_version("0.8.20")

    contract_path = (
        Path(__file__).resolve().parent.parent
        / "smart_contract"
        / "ThreatRegistry.sol"
    )

    source = contract_path.read_text(
        encoding="utf-8"
    )

    compiled = compile_source(
        source,
        output_values=["abi", "bin"]
    )

    contract_data = compiled[
        "<stdin>:ThreatRegistry"
    ]

    return (
        contract_data["abi"],
        contract_data["bin"]
    )


# ============================================================
# DEPLOY SMART CONTRACT
# ============================================================

def deploy_contract():
    if not is_blockchain_connected():
        raise ConnectionError(
            "Ganache is not running."
        )

    abi, bytecode = compile_contract()

    accounts = w3.eth.accounts

    if not accounts:
        raise RuntimeError(
            "No Ganache accounts available."
        )

    account = accounts[0]

    contract = w3.eth.contract(
        abi=abi,
        bytecode=bytecode
    )

    transaction_hash = (
        contract.constructor().transact(
            {
                "from": account,
                "gas": 3000000
            }
        )
    )

    receipt = (
        w3.eth.wait_for_transaction_receipt(
            transaction_hash
        )
    )

    if receipt.status != 1:
        raise RuntimeError(
            "Contract deployment failed."
        )

    contract_address = receipt.contractAddress

    # Save latest contract address
    address_path = (
        Path(__file__).resolve().parent
        / "contract_address.txt"
    )

    address_path.write_text(
        contract_address,
        encoding="utf-8"
    )

    return {
        "contract_address": contract_address,
        "transaction_hash": transaction_hash.hex(),
        "account": account
    }


# ============================================================
# GET DEPLOYED CONTRACT
# ============================================================

def get_contract():
    abi, _ = compile_contract()

    address_path = (
        Path(__file__).resolve().parent
        / "contract_address.txt"
    )

    if not address_path.exists():
        raise FileNotFoundError(
            "contract_address.txt not found. "
            "Deploy the contract first."
        )

    contract_address = (
        address_path.read_text(
            encoding="utf-8"
        ).strip()
    )

    if not contract_address:
        raise ValueError(
            "Contract address is empty."
        )

    return w3.eth.contract(
        address=Web3.to_checksum_address(
            contract_address
        ),
        abi=abi
    )


# ============================================================
# RECORD THREAT ON BLOCKCHAIN
# ============================================================

def record_threat_on_blockchain(
    threat_id: int,
    evidence_hash: str
) -> str:

    if not is_blockchain_connected():
        raise ConnectionError(
            "Ganache is not running."
        )

    accounts = w3.eth.accounts

    if not accounts:
        raise RuntimeError(
            "No Ganache accounts available."
        )

    account = accounts[0]

    contract = get_contract()

    transaction_hash = (
        contract.functions.recordThreat(
            threat_id,
            evidence_hash
        ).transact(
            {
                "from": account,
                "gas": 300000
            }
        )
    )

    receipt = (
        w3.eth.wait_for_transaction_receipt(
            transaction_hash
        )
    )

    if receipt.status != 1:
        raise RuntimeError(
            "Blockchain transaction failed."
        )

    return transaction_hash.hex()


# ============================================================
# READ THREAT FROM BLOCKCHAIN
# ============================================================

def get_threat_from_blockchain(
    threat_id: int
):
    if not is_blockchain_connected():
        raise ConnectionError(
            "Ganache is not running."
        )

    contract = get_contract()

    return contract.functions.getThreat(
        threat_id
    ).call()