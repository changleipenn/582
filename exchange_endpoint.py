from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
from algosdk.future import transaction
from algosdk import account
from hexbytes import HexBytes

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()




def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """


def check_sig(payload2,sig,pk, platform):
        result = False
        try:
            if platform == "Ethereum":
                eth_encoded_msg = eth_account.messages.encode_defunct(text=payload2)
                if (eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == pk):
                    result = True
            elif platform == "Algorand":
                #result = algosdk.util.verify_bytes(message.encode('utf-8'),sig,pk)
                if algosdk.util.verify_bytes(payload2.encode('utf-8'),sig,pk):
                    result = True
            else:
                result = False
            return result
        except:
            print("verification part throw exception")
            result = False
            return result





def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    
    return

#global variable for connection to algo
#acl = connect_to_algo()

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    #check 02: any mnemonic ok?
    #copied from https://github.com/algorand/py-algorand-sdk/blob/develop/test_unit.py
    from algosdk import mnemonic
    mnemonic_secret = (
            "advice pudding treat near rule blouse same whisper inner electric"
            " quit surface sunny dismiss leader blood seat clown cost exist ho"
            "spital century reform able sponsor"
        )
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    
    return algo_sk, algo_pk

#global variable to store account info for ehterem
from web3 import Web3
w3 = Web3()
IP_ADDR='3.23.118.2' #Private Ethereum
PORT='8545'
w3 = Web3(Web3.HTTPProvider('http://' + IP_ADDR + ':' + PORT))
w3.eth.account.enable_unaudited_hdwallet_features()
acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()

def get_eth_keys(filename = "eth_mnemonic.txt"):

    #check 01: does the mnemonic change every time?
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys

    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key


    return eth_sk, eth_pk


def send_algo(acl,  receiver_pk, amt, nonce_offset=0 ):
    
    sender_sk, sender_pk = get_algo_keys() #get_algo_sender()
    return send_tokens_algo( acl, sender_sk, receiver_pk, amt,nonce_offset )

from algosdk.future import transaction
def send_tokens_algo( acl, sender_sk, receiver_pk, tx_amount,nonce_offset=0 ):
	sp = acl.suggested_params()

	sp.last = sp.first + 800 + nonce_offset #Algorand requires sp.last - sp.first < 1000

	sender_pk = account.address_from_private_key(sender_sk)

	# Create and sign transaction
	tx = transaction.PaymentTxn(sender_pk, sp, receiver_pk, tx_amount )
	signed_tx = tx.sign(sender_sk)
   
	tx_success = True
	try:
		print(f"Sending {tx_amount} microalgo from {sender_pk} to {receiver_pk}" )
		tx_confirm = acl.send_transaction(signed_tx)
	except Exception as e:
		tx_success = False
		print( f"Error in send_tokens_algo" )
		print(e)

	if tx_success:
		try:
			txid = signed_tx.transaction.get_txid()
			#txinfo = wait_for_algo_confirmation(acl, txid = txid )
			#print(f"Sent {tx_amount} microalgo in transaction: {txid}\n" )
		except Exception as e:
			print( "algo get_txid failed" )
			print( e )

		return txid
	else:
		return None


def send_eth(w3,receiver_pk,amt,nonce_offset=0):
	sender_sk, sender_pk = get_eth_keys() #get_eth_sender()
	return send_tokens_eth(w3,sender_sk,receiver_pk,amt)

def send_tokens_eth(w3,sender_sk,receiver_pk,amt,nonce_offset=0):
	#w3.eth.account.enable_unaudited_hdwallet_features()
	try:
		sender_account = w3.eth.account.privateKeyToAccount(sender_sk)
	except Exception as e:
		print( "Error in send_tokens_eth" )
		print( e ) 
		return None, None
	sender_pk = sender_account._address

	initial_balance = w3.eth.get_balance(sender_pk)

	nonce = w3.eth.get_transaction_count(sender_pk,'pending')
	nonce += nonce_offset

	tx_dict = {
			'nonce':nonce,
			'gasPrice':w3.eth.gas_price,
			'gas': w3.eth.estimate_gas( { 'from': sender_pk, 'to': receiver_pk, 'data': b'', 'amount': amt } ),
			'to': receiver_pk,
			'value': amt,
			'data':b'' }

	signed_txn = w3.eth.account.sign_transaction(tx_dict, sender_sk)

	in_queue = 0
	try:
		print( f"Sending {tx_dict['value']} WEI from {sender_pk} to {tx_dict['to']}" )
		tx_id = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
	except ValueError as e:
		pending_block = w3.eth.get_block('pending',full_transactions=True)
		pending_txes = pending_block['transactions']
		for tx in pending_txes:
			if tx['to'] == receiver_pk and tx['from'] == sender_pk and tx['value'] == amt and tx['nonce'] == nonce:
				tx_id = tx['hash']
				in_queue = 1
				print( "TX already in queue" )
		if not in_queue:
			print( "Error sending Ethereum transaction" )
			print( f"nonce_offset == {nonce_offset}" )
			print( e )
			if 'message' in e.keys():
				if e['message'] == 'replacement transaction underpriced':
					print( e['message'])
		return None

	#receipt = wait_for_eth_confirmation(tx_hash)
	if isinstance(tx_id,HexBytes):
		tx_id = tx_id.hex()
	return tx_id


def process_order(order):
#     { 
#   'buy_currency': "Algorand",
#   'sell_currency': "Ethereum", 
#   'buy_amount': 1245.00,
#   'sell_amount': 2342.31,
#   'sender_pk': 'AAAAC3NzaC1lZDI1NTE5AAAAIB8Ht8Z3j6yDWPBHQtOp/R9rjWvfMYo3MSA/K6q8D86r',
#   'receiver_pk': '0xd1B77a920A0c5010469F40f14c5e4E03f4357226'
# }
    #Your code here
    #insert order into database
    #Insert the order
    
    order_obj = Order( sender_pk=order['sender_pk'],receiver_pk=order['receiver_pk'], buy_currency=order['buy_currency'], sell_currency=order['sell_currency'], buy_amount=order['buy_amount'], sell_amount=order['sell_amount'])
    if ('creator_id' in order):
        order_obj = Order( sender_pk=order['sender_pk'],receiver_pk=order['receiver_pk'], buy_currency=order['buy_currency'], sell_currency=order['sell_currency'], buy_amount=order['buy_amount'], sell_amount=order['sell_amount'], creator_id=order['creator_id'] )
    
    for order in [order_obj]:
        print("prosessing buy "+ order.buy_currency +" "+ str(order.buy_amount)+ " sell "+ order.sell_currency +" "+ str(order.sell_amount)+" "+str(order.filled) +" "+str(order.creator_id))

    g.session.add(order_obj)
    g.session.flush()
    print(order_obj.id)
    g.session.commit()



    

    #check if there are existing orders that match
    def getBuySellRatio(obj):
        return obj.buy_amount/obj.sell_amount
    

    matchOrders = g.session.query(Order).filter(Order.filled == None, 
    Order.buy_currency == order_obj.sell_currency, 
    Order.sell_currency == order_obj.buy_currency,
    Order.sell_amount*order_obj.sell_amount>=Order.buy_amount*order_obj.buy_amount,
    Order.id != order_obj.id
    ).all()
    
    

    if len(matchOrders) == 0:
        return
    else:

        matchOrders.sort(key=getBuySellRatio)
        matchOrder = matchOrders[0]

    



    #if match is found between order and existing order
        matchOrder.filled = datetime.now()
        order_obj.filled =datetime.now()

        #fill transaction 
        # matchOrder(buy_currency, min(matchorder.buy_amount,order_obj.sell_amount ) sender_pk
        # order_obj(buy_currency, min(order_obj.buy_amount,matchOrder.sell_amount) sender_pk
        if matchOrder.buy_currency == "Algorand":  #matchorder buy algorand sell eth,
            txid1 = send_algo(g.acl,  matchOrder.receiver_pk, min(matchOrder.buy_amount,order_obj.sell_amount ) , nonce_offset=0 ) #send algo to the matchOrder
            matchOrder.tx_id = txid1
            txid2 = send_eth(w3,order_obj.receiver_pk,min(order_obj.buy_amount,matchOrder.sell_amount),nonce_offset=0)#send eth to the order_obj
            order_obj.tx_id = txid2
            g.session.flush()
            g.session.commit()
        else:
            txid1 = send_eth(w3,  matchOrder.receiver_pk, min(matchOrder.buy_amount,order_obj.sell_amount ) , nonce_offset=0 ) #send algo to the matchOrder
            matchOrder.tx_id = txid1
            txid2 = send_algo(g.acl,order_obj.receiver_pk,min(order_obj.buy_amount,matchOrder.sell_amount),nonce_offset=0)#send eth to the order_obj
            order_obj.tx_id = txid2
            g.session.flush()
            g.session.commit()

        matchOrder.counterparty_id=order_obj.id
        order_obj.counterparty_id=matchOrder.id
        g.session.flush()
        g.session.commit()
        if matchOrder.buy_amount > order_obj.sell_amount:
                order_dict = { 
                        'buy_currency': matchOrder.buy_currency,
                        'sell_currency': matchOrder.sell_currency, 
                        'buy_amount': matchOrder.buy_amount-order_obj.sell_amount,
                        'sell_amount': matchOrder.sell_amount-order_obj.buy_amount,
                        'sender_pk': matchOrder.sender_pk,
                        'receiver_pk': matchOrder.receiver_pk,
                        'creator_id':matchOrder.id
                        }
                process_order(order_dict)

        elif order_obj.buy_amount > matchOrder.sell_amount:
                order_dict = { 
                        'buy_currency': order_obj.buy_currency,
                        'sell_currency': order_obj.sell_currency, 
                        'buy_amount': order_obj.buy_amount-matchOrder.sell_amount,
                        'sell_amount': order_obj.sell_amount-matchOrder.buy_amount,
                        'sender_pk': order_obj.sender_pk,
                        'receiver_pk': order_obj.receiver_pk,
                        'creator_id':order_obj.id
                        }
                process_order(order_dict)

        else:
            print("both order filled")




    pass




def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    
    pass
  


def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    pass

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            eth_sk, eth_pk = get_eth_keys()
            #Your code here
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            algo_sk, algo_pk = get_algo_keys()
            #Your code here
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    #get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        sig = content['sig']
        pk = content['payload']['sender_pk']
        platform = content['payload']['platform']
        payload = content['payload']
        payload2= json.dumps(payload)
        tx_id = payload["tx_id"]
        order = {'sender_pk': payload['sender_pk'],
             'receiver_pk': payload['receiver_pk'],
            'buy_currency': payload['buy_currency'],
            'sell_currency': payload['sell_currency'],
            'buy_amount': payload['buy_amount'],
            'sell_amount': payload['sell_amount'],
            'signature':sig
            }
        order_obj = Order( sender_pk=order['sender_pk'],
         receiver_pk=order['receiver_pk'],
         buy_currency=order['buy_currency'], 
         sell_currency=order['sell_currency'], 
         buy_amount=order['buy_amount'], 
         sell_amount=order['sell_amount'],
         signature=order['signature'] )

        logError = {'message':payload2}
        log_obj = Log(message = logError['message'])

        #check signature
        result = check_sig(payload2,sig,pk, platform)
        
        # 2. Add the order to the table
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        if order['sell_currency'] == "Ethereum":
            tx = w3.eth.get_transaction(tx_id)
            amount = tx["value"]
            receiver = tx["to"]
            if not (amount == order['sell_amount'] and receiver == get_eth_keys()[1]):
                print( f"Error: algorand not received by server" )
                return jsonify( "Error: algorand not received by server" )
        elif order["sell_currency"]=="Algorand":
            indexer = connect_to_algo(connection_type="indexer")
            tx = indexer.search_transactions(txid =tx_id)
            amount = tx["transactions"][0]["payment-transaction"]["amount"]
            receiver = tx["transactions"][0]["payment-transaction"]["receiver"]
            if not (amount == order['sell_amount'] and receiver == get_algo_keys()[1]):
                print( f"Error: algorand not received by server" )
                return jsonify( "Error: algorand not received by server" )

        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        # 4. Execute the transactions
                #If the signature verifies, store the signature, as well as all of the fields under the ‘payload’ in the “Order” 
        # #table EXCEPT for 'platform’.
        if result:
            # g.session.add(order_obj)
            # g.session.commit()
            # return jsonify(order)
            process_order(order)
            printOrderBook()


            return jsonify(True)
            

        # If the signature does not verify, do not insert the order into the “Order” table.
        # Instead, insert a record into the “Log” table, with the message field set to be json.dumps(payload).
        else:
            g.session.add(log_obj)
            g.session.commit()
            return jsonify(False)

def printOrderBook():
            print("current order book")
            for u in g.session.query(Order).all():
                dic = u.__dict__
                newDic = {k:dic[k] for k in ["sender_pk","receiver_pk","buy_currency",
                "sell_currency","buy_amount","sell_amount","signature","tx_id","filled","creator_id"]}
                print("buy "+newDic["buy_currency"] +" "+ str(newDic["buy_amount"] )+ " sell "+ newDic["sell_currency"]  +" "+ str(newDic["sell_amount"] )+" "+ str(newDic["tx_id"]) +" "+str(newDic["filled"]) +" "+str(newDic["creator_id"]))

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    result = []
    for u in g.session.query(Order).all():
        dic = u.__dict__
        newDic = {k:dic[k] for k in ["sender_pk","receiver_pk","buy_currency","sell_currency","buy_amount","sell_amount","signature","tx_id"]}
        result.append(newDic)
        
    res2 = {"data":result}

    return jsonify(res2)

if __name__ == '__main__':
    app.run(port='5002')
