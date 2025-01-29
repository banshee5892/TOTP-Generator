from flask import Flask, request, jsonify
import subprocess
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
   return '''
   <!DOCTYPE html>
   <html>
   <head>
       <title>TOTP Generator</title>
       <script src="https://cdn.tailwindcss.com"></script>
   </head>
   <body class="bg-gray-100">
       <div class="container mx-auto px-4 py-8">
           <div class="max-w-md mx-auto bg-white rounded-xl shadow-md p-6">
               <h1 class="text-2xl font-bold mb-6">TOTP Generator</h1>
               <form id="totpForm" class="space-y-4">
                   <div>
                       <label class="block text-sm font-medium">Secret Key</label>
                       <input type="text" name="secret" required class="mt-1 block w-full rounded-md border border-gray-300 p-2">
                   </div>
                   <div>
                       <label class="block text-sm font-medium">Digits</label>
                       <input type="number" name="digits" value="6" class="mt-1 block w-full rounded-md border border-gray-300 p-2">
                   </div>
                   <div>
                       <label class="block text-sm font-medium">Interval</label>
                       <input type="number" name="interval" value="30" class="mt-1 block w-full rounded-md border border-gray-300 p-2">
                   </div>
                   <div class="flex items-center space-x-4">
                       <div class="flex items-center">
                           <input type="checkbox" name="debug" id="debug" class="h-4 w-4">
                           <label for="debug" class="ml-2">Debug Mode</label>
                       </div>
                       <input type="text" name="debug_value" id="debug_value" 
                              class="hidden mt-1 w-32 rounded-md border border-gray-300 p-2" 
                              placeholder="Debug value">
                   </div>
                   <button type="submit" class="w-full bg-blue-500 text-white p-2 rounded-md hover:bg-blue-600">Generate</button>
               </form>
               <div id="result" class="mt-4 p-4 hidden"></div>
               <div id="command" class="mt-4 p-4 hidden font-mono text-sm"></div>
           </div>
       </div>

       <script>
           document.getElementById('debug').addEventListener('change', (e) => {
               document.getElementById('debug_value').classList.toggle('hidden', !e.target.checked);
           });

           document.getElementById('totpForm').addEventListener('submit', async (e) => {
               e.preventDefault();
               const form = e.target;
               const resultDiv = document.getElementById('result');
               const commandDiv = document.getElementById('command');
               
               const data = {
                   secret: form.secret.value,
                   digits: parseInt(form.digits.value),
                   interval: parseInt(form.interval.value),
                   debug: form.debug.checked,
                   debug_value: form.debug.checked ? form.debug_value.value : ''
               };

               try {
                   const response = await fetch('/api/totp', {
                       method: 'POST',
                       headers: {'Content-Type': 'application/json'},
                       body: JSON.stringify(data)
                   });

                   const result = await response.json();
                   resultDiv.className = `mt-4 p-4 border rounded ${response.ok ? 'bg-green-50' : 'bg-red-50'}`;
                   resultDiv.innerHTML = response.ok ? 
                       `<pre>${result.output || 'No output'}</pre>` +
                       (result.error ? `<pre class="text-red-500 mt-2">${result.error}</pre>` : '') :
                       `<div class="text-red-500">${result.error}</div>`;
                   resultDiv.classList.remove('hidden');

                   // Display command
                   commandDiv.className = 'mt-4 p-4 bg-gray-100 border rounded';
                   commandDiv.innerHTML = `<div>Executed command:</div><pre>${result.command}</pre>`;
                   commandDiv.classList.remove('hidden');
               } catch (error) {
                   resultDiv.className = 'mt-4 p-4 bg-red-50 border rounded';
                   resultDiv.innerHTML = `<div class="text-red-500">Error: ${error.message}</div>`;
                   resultDiv.classList.remove('hidden');
               }
           });
       </script>
   </body>
   </html>
   '''

@app.route('/api/totp', methods=['POST'])
def generate_totp():
   try:
       data = request.json
       if not data.get('secret'):
           return jsonify({'error': 'Secret key required'}), 400
           
       command = ['TOTP.exe', '--secret', str(data['secret'])]
       if data.get('digits'): command.extend(['--digits', str(data['digits'])])
       if data.get('interval'): command.extend(['--interval', str(data['interval'])])
       if data.get('debug'): 
           debug_value = data.get('debug_value', '').strip()
           if debug_value:
               command.append('--debug')
               command.append(debug_value)
           else:
               command.append('--debug')

       command_str = ' '.join(command)
       logger.info(f"Executing: {command_str}")
       
       result = subprocess.run(' '.join(command), shell=True, capture_output=True, text=True)
       
       logger.info(f"Output: {result.stdout}")
       if result.stderr:
           logger.error(f"Error: {result.stderr}")

       return jsonify({
           'command': command_str,
           'output': result.stdout,
           'error': result.stderr
       })
   except Exception as e:
       logger.exception("Error executing TOTP command")
       return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
   app.run(host='0.0.0.0', port=5000, debug=True)