# Intentionally vulnerable: eval and exec usage
user_input = request.form.get('expression')
result = eval(user_input)
exec(compile(user_code, '<string>', 'exec'))
