from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/', methods=['GET'])
def execute_command():
    commandid = request.args.get('cmdid')
    if commandid == '1' :
        command = "dir"
    elif commandid == '2' :
        command = "type flag.txt"
    else:
        return "Please provide a 'cmdid' parameter in the URL."

    if command:
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            return result, 200
        except subprocess.CalledProcessError as e:
            return f"Error: {e.output}", 400

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80)
