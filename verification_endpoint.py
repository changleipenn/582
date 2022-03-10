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

    if platform == "Ethereum":
        result = eth_account.Account.recover_message(payload,sig.hex()) == pk
    else:
        result = algosdk.util.verify_bytes(payload.encode('utf-8'),sig,pk)

    result = True #Should only be true if signature validates
    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')
