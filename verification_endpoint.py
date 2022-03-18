from flask import Flask, request, jsonify
from flask_restful import Api
import json
import eth_account
import algosdk

app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False

@app.route('/verify', methods=['GET','POST'])
def verify():
    content = request.get_json(silent=True)

    #Check if signature is valid
    sig = content['sig']
    message = content['payload']['message']
    pk = content['payload']['pk']
    platform = content['payload']['platform']
    payload = content['payload']
    payload2= json.dumps(payload)

    #check result
    result = False
    if platform == "Ethereum":
        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload2)
        if (eth_account.Account.recover_message(eth_encoded_msg,sig) == pk):
            result = True
    elif platform == "Algorand":
        #result = algosdk.util.verify_bytes(message.encode('utf-8'),sig,pk)
        if algosdk.util.verify_bytes(payload2.encode('utf-8'),sig,pk):
            result = True
    else:
        result = False

    #result = True #Should only be true if signature validates
    

    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')
