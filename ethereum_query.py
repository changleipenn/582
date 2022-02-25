from web3 import Web3
from hexbytes import HexBytes

IP_ADDR='18.188.235.196'
PORT='8545'

w3 = Web3(Web3.HTTPProvider('http://' + IP_ADDR + ':' + PORT))

#if w3.isConnected():
#     This line will mess with our autograders, but might be useful when debugging
#     print( "Connected to Ethereum node" )
#else:
#    print( "Failed to connect to Ethereum node!" )



def get_transaction(tx):
    tx = {}   #YOUR CODE HERE
    return tx

# Return the gas price used by a particular transaction,
#   tx is the transaction
def get_gas_price(tx):
    gas_price = w3.eth.get_transaction(tx).gasPrice #YOUR CODE HERE
    return gas_price

def get_gas(tx):
    gasDS = w3.eth.get_transaction_receipt(tx).gasUsed
    #gas = 1 #YOUR CODE HERE
    return gasDS

def get_transaction_cost(tx):
    tx_cost = get_gas(tx)*get_gas_price(tx) #YOUR CODE HERE
    return tx_cost

def get_block_cost(block_num):
    block_cost=0
    for t in  w3.eth.get_block(block_num).transactions:
        block_cost += get_transaction_cost(t)
    return block_cost

# Return the hash of the most expensive transaction
def get_most_expensive_transaction(block_num):
    maxCost=0
    max_tx = None
    for t in  w3.eth.get_block(block_num).transactions:
        if get_transaction_cost(t)>maxCost:
            maxCost = get_transaction_cost(t)
            max_tx = HexBytes(t)
    return max_tx


#get_gas_price(NULL)