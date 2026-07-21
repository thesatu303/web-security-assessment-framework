from flask import Flask, render_template, request, jsonify
import subprocess
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target')
    output_file = data.get('output', 'report.pdf')
    
    try:
        # Run main.py with target
        result = subprocess.run(
            ['python', 'main.py', '--target', target, '--output', output_file],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        return jsonify({
            'success': True,
            'message': 'Scan completed successfully!',
            'output': output_file,
            'stdout': result.stdout
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })

# Add this to app.py for payload info

@app.route('/payloads')
def payloads_info():
    from sql_injection import SQLInjectionTester
    tester = SQLInjectionTester('http://dummy.com', {})
    total, categories = tester.count_payloads()
    
    return jsonify({
        'total_payloads': total,
        'categories': len(categories),
        'categories_list': list(tester.payloads.keys())
    })
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)