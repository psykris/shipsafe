# Intentionally vulnerable: pickle with untrusted data
import pickle
data = pickle.loads(request.data)
obj = pickle.load(open('user_upload.pkl', 'rb'))
