Take the configuration-via-convention idea from rails, and add in REST's
URI-as-persistence.

A simple todo app with journal looks like:

	import resty

	def db_setup():
		resty.db_exec( 'init.sql' )

	def users_new(req):
		resty.db_exec(' insert into users values ( ?, ?, ? ) ', (
			req.input['username'],
			resty.auth_password(req.input['password']),
			req.input['email']
		))
		return resty.http_ok('')

	resty.run(
		prefix = '/app',
		database = 'db-app.sqlite',
		exposed_tables = ['todos', 'journals'],
		functions = locals()
	)

ROUTES are created for any function ending in ['_list', '_new', '_get', '_set',
'_del'] -- e.g. users_new() handles POSTS to /app/users

Any functions ending in '_setup' are run prior to the WSGI server loop --
e.g. db_setup() creates the tables for users, todos, and journals.

Each of the exposed_tables have the 5 routing functions automatically created,
each with the @auth_required decorator.


