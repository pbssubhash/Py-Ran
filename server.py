from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import pgpy
import sys
import base64

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), post_data.decode('utf-8'))
        pgp_message = post_data.decode('utf-8')
        pgp_message = pgp_message[9:]
        pgp_message = pgp_message[:-3]
        print(pgp_message)
        b64_decoded_pgp_message = base64.b64decode(pgp_message)
        print(b64_decoded_pgp_message)
        encrypted_message = pgpy.PGPMessage.from_file("C:\\Users\\floof\\Py-Ran\\test_aes.txt")
        privkey = "C:\\Users\\floof\\pgp\\private.gpg"
        key,_ = pgpy.PGPKey.from_file(privkey)
        key.protect("C0rrectPassphr@se", pgpy.constants.SymmetricKeyAlgorithm.AES256, pgpy.constants.HashAlgorithm.SHA256)
        print("am I nlocked : " + str(key.is_protected))
        with key.unlock('C0rrectPassphr@se'):
            decrypted_message = key.decrypt(encrypted_message)
            aes_key = decrypted_message.message
            print(key)

            self._set_response()
            self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()