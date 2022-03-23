from tokenize import Double
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from models import Base, Order
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

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

    session.add(order_obj)
    session.flush()
    print(order_obj.id)
    session.commit()



    

    #check if there are existing orders that match
    def getBuySellRatio(obj):
        return obj.buy_amount/obj.sell_amount
    

    matchOrders = session.query(Order).filter(Order.filled == None, 
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

