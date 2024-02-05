from flask import Flask, render_template, request, send_file
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os


def create_app():
    app = Flask(__name__)

    KEY_DIR = '../keys'

    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

    def generate_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_key_pem, public_key_pem

    def save_key_to_file(key_data, key_type):
        filename = f'{KEY_DIR}/{key_type}_key.pem'
        with open(filename, 'wb') as f:
            f.write(key_data)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/generate_keys', methods=['POST'])
    def generate_keys():
        private_key_pem, public_key_pem = generate_key_pair()

        save_key_to_file(private_key_pem, 'private')
        save_key_to_file(public_key_pem, 'public')

        return render_template('index.html', message='Keys generated successfully!')

    @app.route('/encrypt', methods=['POST'])
    def encrypt():
        try:
            message = request.form['message']
            public_key = request.files['public_key'].read()

            public_key_obj = serialization.load_pem_public_key(public_key)
            ciphertext = public_key_obj.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return render_template('index.html', encrypted_message=ciphertext.hex())

        except Exception as e:
            return render_template('index.html', error=str(e))

    @app.route('/decrypt', methods=['POST'])
    def decrypt():
        try:
            encrypted_message = request.form['encrypted_message']
            private_key = request.files['private_key'].read()

            private_key_obj = serialization.load_pem_private_key(private_key, password=None)
            decrypted_message = private_key_obj.decrypt(
                bytes.fromhex(encrypted_message),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()

            return render_template('index.html', decrypted_message=decrypted_message)

        except Exception as e:
            return render_template('index.html', error=str(e))

    @app.route('/download/<key_type>')
    def download_key(key_type):
        try:
            if key_type == 'private':
                filename = f'{KEY_DIR}/private_key.pem'
            elif key_type == 'public':
                filename = f'{KEY_DIR}/public_key.pem'
            else:
                return render_template('index.html', error='Invalid key type')

            return send_file(filename, as_attachment=True)

        except Exception as e:
            return render_template('index.html', error=str(e))

    return app


if __name__ == "__main__":
    my_app = create_app()
    my_app.run(debug=True)
