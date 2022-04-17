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
import sys

from models import Base, Order, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


""" Suggested helper methods """

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

def fill_order(order,txes=[]):
    pass


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
    
    order_obj = Order( sender_pk=order['sender_pk'],receiver_pk=order['receiver_pk'], buy_currency=order['buy_currency'], sell_currency=order['sell_currency'], buy_amount=order['buy_amount'], sell_amount=order['sell_amount'] )
    if ('creator_id' in order):
        order_obj = Order( sender_pk=order['sender_pk'],receiver_pk=order['receiver_pk'], buy_currency=order['buy_currency'], sell_currency=order['sell_currency'], buy_amount=order['buy_amount'], sell_amount=order['sell_amount'], creator_id=order['creator_id'] )
    
    for order in [order_obj]:
        print( order.buy_currency +" "+ str(order.buy_amount)+ " "+ order.sell_currency +" "+ str(order.sell_amount)+" "+str(order.filled) +" "+str(order.creator_id))

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
        matchOrder.counterparty_id=order_obj.id
        order_obj.counterparty_id=matchOrder.id
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



def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    # Hint: use json.dumps or str() to get it in a nice string form
    pass

""" End of helper methods """


@app.route('/')
def home():
    return "Hello, Flask!"

@app.route('/trade', methods=['POST'])
def trade():
    print("In trade endpoint")
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]

        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
            
        #Your code here
        #Note that you can access the database session using g.session

        # TODO: Check the signature
        
        # TODO: Add the order to the database
        
        # TODO: Fill the order
        
        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful
        sig = content['sig']
        pk = content['payload']['sender_pk']
        platform = content['payload']['platform']
        payload = content['payload']
        payload2= json.dumps(payload)
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

        #If the signature verifies, store the signature, as well as all of the fields under the ‘payload’ in the “Order” 
        # #table EXCEPT for 'platform’.
        if result:
            # g.session.add(order_obj)
            # g.session.commit()
            # return jsonify(order)
            process_order(order)
            return jsonify(True)
            

        # If the signature does not verify, do not insert the order into the “Order” table.
        # Instead, insert a record into the “Log” table, with the message field set to be json.dumps(payload).
        else:
            g.session.add(log_obj)
            g.session.commit()
            return jsonify(False)


@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    result = []
    for u in g.session.query(Order).all():
        dic = u.__dict__
        newDic = {k:dic[k] for k in ["sender_pk","receiver_pk","buy_currency","sell_currency","buy_amount","sell_amount","signature"]}
        result.append(newDic)
        
    res2 = {"data":result}

    return jsonify(res2)

if __name__ == '__main__':
    app.run(port='5002')