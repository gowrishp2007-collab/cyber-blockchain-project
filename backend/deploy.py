from backend.blockchain import deploy_contract


result = deploy_contract()

print("Contract deployed successfully")
print("Contract Address:", result["contract_address"])
print("Transaction Hash:", result["transaction_hash"])
print("Deployer Account:", result["account"])