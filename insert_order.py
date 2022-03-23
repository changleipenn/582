from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import random
from models import Base, Order

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

session = DBSession()

platforms = ["Algorand", "Ethereum"] 
platform = "Ethereum"
sender_pk = hex(random.randint(0,2**256))[2:] #Generate random string that looks like a public key
receiver_pk = hex(random.randint(0,2**256))[2:] #Generate random string that looks like a public key

other_platform = platforms[1-platforms.index(platform)]

# ####################################################################
# ##insert order
# #Generate random order data

order = {}
order['sender_pk'] = sender_pk
order['receiver_pk'] = receiver_pk
order['buy_currency'] = other_platform
order['sell_currency'] = platform
order['buy_amount'] = random.randint(1,10)
order['sell_amount'] = random.randint(1,10)


#Insert the order
order_obj = Order( sender_pk=order['sender_pk'],receiver_pk=order['receiver_pk'], buy_currency=order['buy_currency'], sell_currency=order['sell_currency'], buy_amount=order['buy_amount'], sell_amount=order['sell_amount'] )

# #Alternatively, this code inserts the same record and is arguably more readable
# fields = ['sender_pk','receiver_pk','buy_currency','sell_currency','buy_amount','sell_amount']
# order_obj = Order(**{f:order[f] for f in fields})

###########################################################
#insert object get id
session.add(order_obj)
session.flush()
print(order_obj.id)
session.commit()

orders=session.query(Order).all()
for order in orders:
    print( order.buy_currency +" "+ str(order.buy_amount)+ " "+ order.sell_currency +" "+ str(order.sell_amount) )


####################################################################
#update
session.query(Order).filter(Order.id == 2).update({Order.buy_amount:(Order.buy_amount+1)}, synchronize_session = False)
session.commit()


################################################
##select where
norders = session.query(Order).filter(Order.buy_amount/Order.sell_amount>1).order_by(Order.buy_amount/Order.sell_amount)
print("two where")
for order in norders:
    print( order.buy_currency + str(order.buy_amount)+ " "+ order.sell_currency + str(order.sell_amount) )

session.close()
# #update
# user = User.query.filter_by(username=form.username.data).first()
# user.no_of_logins += 1
# session.commit()



# from sqlalchemy.sql import text
# engine = create_engine('sqlite:///orders.db')
# with engine.connect() as con:


#     order = {}
#     order['sender_pk'] = sender_pk
#     order['receiver_pk'] = receiver_pk
#     order['buy_currency'] = other_platform
#     order['sell_currency'] = platform
#     order['buy_amount'] = random.randint(1,10)
#     order['sell_amount'] = random.randint(1,10)
#     #Alternatively, this code inserts the same record and is arguably more readable
#     fields = ['sender_pk','receiver_pk','buy_currency','sell_currency','buy_amount','sell_amount']
#     order_obj = (order)
        


#     statement = text("""INSERT INTO Order('sender_pk','receiver_pk','buy_currency','sell_currency','buy_amount','sell_amount') VALUES(:sender_pk,:receiver_pk,:buy_currency,:sell_currency,:buy_amount,:sell_amount)""")

#     for line in order_obj:
#         con.execute(statement, **line)

# with engine.connect() as con:

#     rs = con.execute('SELECT * FROM Order')

#     for row in rs:
#         print (row)