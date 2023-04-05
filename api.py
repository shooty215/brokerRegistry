#!/bin/python3
from PROPERTIES.py import CERT_PATH, KEY_PATH
from flask import Flask, request
import ssl

app = Flask(__name__)

@app.route('/cert/distribution', methods=['POST'])
def cert_distribution():
    # Check for the api-token and channel name parameters in the request
    api_token = request.args.get('api-token')
    user_token = request.args.get('user-token')
    channel_name = request.args.get('channel-name')

    # Validate the api-token and channel name
    if api_token is None or user_token is None or channel_name is None:
        return 'Missing api-token or channel name', 400

    # TODO: Implement your certificate distribution logic here

    return 'Certificate distribution successful'

@app.route('/cert/creation/ca', methods=['POST'])
def cert_distribution():
    # Check for the api-token and channel name parameters in the request
    api_token = request.args.get('api-token')
    creator_token = request.args.get('creator-token')
    channel_name = request.args.get('channel-name')

    # Validate the api-token and channel name
    if api_token is None or creator_token is None or channel_name is None:
        return 'Missing request parameter', 400

    # TODO: Implement your certificate distribution logic here

    return 'Certificate distribution successful'

@app.route('/cert/creation/broker', methods=['POST'])
def cert_distribution():
    # Check for the api-token and channel name parameters in the request
    api_token = request.args.get('api-token')
    creator_token = request.args.get('creator-token')
    channel_name = request.args.get('channel-name')

    # Validate the api-token and channel name
    if api_token is None or creator_token is None or channel_name is None:
        return 'Missing request parameter', 400

    # TODO: Implement your certificate distribution logic here

    return 'Certificate distribution successful'

@app.route('/cert/creation/client', methods=['POST'])
def cert_distribution():
    # Check for the api-token and channel name parameters in the request
    api_token = request.args.get('api-token')
    creator_token = request.args.get('creator-token')
    channel_name = request.args.get('channel-name')

    # Validate the api-token and channel name
    if not Service.Validation().__validateApiInputs(api_token, creator_token, channel_name):
        return 'Missing request parameter', 400

    # TODO: Implement your certificate distribution logic here

    return 'Certificate distribution successful'

class Service:

    class Validation:

        def __validateContextCreation() -> bool:
            return True
        
        def __validateBashScriptExecution() -> bool:
            return True

        def __validateApiInputs(token: str or None, token: str or None, channel: str or None) -> bool:
            return api_token is None or creator_token is None or channel_name is None
        
    def __createTlsContext() -> SSLContext:
        context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION
        context.set_ciphers('ECDHE+AESGCM')
        context.set_alpn_protocols(['h2', 'http/1.1'])
        context.set_npn_protocols(['h2', 'http/1.1'])
        context.load_cert_chain(CERT_PATH, KEY_PATH)
        return context

    def __runBashScript() -> bool:
        return True
    
    
# Run the app
if __name__ == '__main__':
    app.run(ssl_context=context)
