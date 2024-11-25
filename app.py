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
#
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
# sink parsing : vulnerable_yaml / yaml / load      
@app.route('/yaml', methods=['GET'])
def vulnerable_yaml():
    # GET 요청의 'data' 파라미터로 전달된 YAML 데이터를 가져옴
    yaml_data = request.args.get('data')  
    try:
        # YAML 데이터를 파싱함 (주의: yaml.load는 비신뢰성 입력에 대해 위험할 수 있음)
        data = yaml.load(yaml_data, Loader=yaml.Loader)
        # 성공적으로 파싱된 데이터를 JSON 형식으로 반환
        return jsonify({"message": "YAML parsed successfully", "content": data})
    except Exception as e:
        # 에러 발생 시 에러 메시지를 JSON 형식으로 반환
        return jsonify({"error": str(e)}), 400

# markdown == 3.1.1
# POC : curl "http://127.0.0.1/markdown?content=<script>alert('XSS')</script>"
# sink parsing : vulnerable_markdown / markdown / markdown
@app.route('/markdown', methods=['GET'])
def vulnerable_markdown():
    # GET 요청의 'content' 파라미터로 전달된 마크다운 형식의 데이터를 가져옴, 기본값은 빈 문자열
    content = request.args.get('content', '')
    # 전달된 마크다운 데이터를 HTML로 변환
    html_output = markdown.markdown(content)
    # 변환된 HTML을 그대로 출력
    return Markup(html_output)

@app.route('/markup', methods=['GET'])
def vulnerable_markupsafe():
    # GET 요청의 'content' 파라미터로 전달된 데이터를 가져옴, 기본값은 빈 문자열
    content = request.args.get('content', '')
    # 사용자 입력 데이터를 Markup 객체로 래핑
    unsafe_output = Markup(content)
    # 변환된 HTML을 그대로 출력
    return unsafe_output

# lxml
# POC : curl "http://127.0.0.1/parse_xml?data=%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E%0A%3C%21DOCTYPE+root+%5B%0A++%3C%21ELEMENT+root+ANY+%3E%0A++%3C%21ENTITY+xxe+SYSTEM+%22file%3A%2F%2F%2Fetc%2Fpasswd%22+%3E%5D%3E%0A%3Croot%3E%26xxe%3B%3C%2Froot%3E"
# parse_xml / lxml /      
@app.route('/parse_xml', methods=['GET'])
def vulnerable_xml():
    try:
        # GET 요청의 'data' 파라미터로 전달된 XML 데이터를 가져옴, 기본값은 빈 문자열
        xml_data = request.args.get('data', '')
        # XML 파서를 설정: DTD 로딩 및 엔티티 해석을 활성화
        parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
        # 전달된 XML 데이터를 UTF-8로 인코딩하여 파싱함
        root = etree.fromstring(xml_data.encode('utf-8'), parser)
        # 파싱된 XML 데이터를 pretty print 형식으로 문자열로 변환함
        root_content = etree.tostring(root, pretty_print=True).decode('utf-8')
        # 성공 메시지와 함께 XML의 루트 태그 및 내용을 JSON 형식으로 반환
        return jsonify({'message': 'XML parsed successfully', 'root_tag': root.tag, 'content': root_content}), 200
    except Exception as e:
        # 에러 발생 시 에러 메시지를 JSON 형식으로 반환
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, port=80)
