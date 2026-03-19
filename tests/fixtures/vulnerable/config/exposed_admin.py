# Intentionally vulnerable: exposed admin/debug routes
from flask import Flask
app = Flask(__name__)

@app.route('/admin')
def admin_panel():
    return render_template('admin.html')

@app.route('/debug')
def debug_info():
    return jsonify(debug_data)
