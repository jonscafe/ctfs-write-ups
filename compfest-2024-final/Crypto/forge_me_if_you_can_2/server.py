import json
from web3 import Web3

# Ethereum node URL
RPC_URL = "https://mainnet.optimism.io"
w3 = Web3(Web3.HTTPProvider(RPC_URL))

FLAG = "COMPFEST16{bukan_chall_blockchen_sumpah(ini fake flag)}"

# Contract address and ABI
CONTRACT_ADDRESS = "0xC32b1B8D6e8103A9E4c6f3Ee05e5D6adA0903755"
CONTRACT_ABI = json.loads('[{"inputs":[{"internalType":"uint256","name":"r","type":"uint256"},{"internalType":"uint256","name":"s","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bool","name":"isGetFlag","type":"bool"}],"name":"forgeSignature","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"nonpayable","type":"function"}]')

# Constants from the contract
SIGNER = "0xCF163fC1082De8CB79ce754BFE25B06EC490Ebac"
SIGM_ADDRESS = "0xcf16888A36BC584EC6e22f175bC290C3e50BDd47"

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

def simulate_forge_signature(r, s, v, is_get_flag):
    # Create the transaction
    tx = contract.functions.forgeSignature(r, s, v, is_get_flag).build_transaction({
        'from': SIGNER,
        'gas': 2000000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(SIGNER),
    })
    
    # Simulate the transaction
    try:
        result = w3.eth.call(tx)
        return w3.to_text(result)
    except Exception as e:
        return f"Simulation failed: {str(e)}"

def main():
    print("===================== Try to forge my signature =====================")
    print("Since you will be bored trying to brute force the signature, here are some random quote : ")
    print("~~~ There is no sorrow greater than parting in life, and no joy greater than meeting someone new. ~~~")
    while True:
        choice = input("Choose '1' for Part1 or '2' for For the full challenge (and the flag): ")
        if choice == '1':
            print("Enter the r, s, v values for the signature:")
            r = int(input("r (as a decimal integer): "))
            s = int(input("s (as a decimal integer): "))
            v = int(input("v : "))

            result = simulate_forge_signature(r, s, v, False)
            if "Part1Success" in result:
                print("Part Success! Now come the hard part, maybe")
            else:
                print(f"Failed. Result: {result}")
        elif choice == '2':
            print("Enter the r, s, v values for the signature:")
            r = int(input("r (as a decimal integer): "))
            s = int(input("s (as a decimal integer): "))
            v = int(input("v :"))
            result = simulate_forge_signature(r, s, v, True)
            if "HiServerCanYouGibTheFlag???" in result:
                print(f"Success! The flag is: {FLAG}")
            else:
                print(f"Failed to get the flag. Result: {result}")
        else:
            print("Invalid choice. Please run the script again and choose '1' or '2'.")

if __name__ == "__main__":
    main()