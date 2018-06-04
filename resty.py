#!/usr/bin/env python3
import wsgiref.simple_server, json, re, sqlite3, os
from collections import namedtuple
from hashlib import sha256
from base64 import b64decode

debug = print
sql_safe = lambda word: re.compile('[^A-Za-z_]').sub('', word)

def db_connect():
    db = sqlite3.connect(CFG.database)
    db.row_factory = lambda cur,row: { col[0] : row[i] for i, col in enumerate(cur.description) }
    return db

def db_exec(*args):
    db = db_connect()
    c = db.cursor()
    ret = None
    if len(args) == 1 and os.path.isfile(args[0]):
        c.executescript( open(args[0]).read() )
    else:
        c.execute(*args)
        ret = c.lastrowid
    db.commit()
    db.close()
    return ret

def db_rows(*args):
    db = db_connect()
    c = db.cursor()
    c.execute(*args)
    ret = c.fetchall()
    db.close()
    return ret

def test_db():
    global CFG
    db_file = '/tmp/test-resty.db'
    CFG = namedtuple('Config', 'database')( db_file )
    try:
        db_exec(''' create table test ( foo text ) ''')
        db_exec(''' insert into test values ( ? ) ''', ('bar', ))
        r = db_rows(''' select * from test  ''')
    finally:
        os.remove(db_file)
    assert r == [{'foo':'bar'}]

def auth_basic(env):
    fail = (None, None)
    hdr = None
    for e in ('HTTP_AUTHORIZATION', 'AUTHORIZATION'):
        if e in env:
            hdr = env[e]
            break
    else:
        debug("no auth header found in env, returning fail")
        return fail
    if hdr is None or hdr[0:5] != 'Basic':
        return fail
    try:
        username, password = b64decode(hdr[6:].strip()).decode().split(':')
        return username, password
    except:
        return fail

def auth_password(plain):
    try:
        plain = plain.encode()
    except:
        pass
    return sha256(plain).hexdigest()

def test_auth():
    global debug
    debug = lambda *a: None
    assert auth_basic( { 'AUTHIZATION': 'Basic QWxhZGRpbjpPcGVuzYW1l' }) == (None, None)
    assert auth_basic( { 'AUTHORIZATION': 'Basic QWxhZGRpbjpPcGVuzYW1l' }) == (None, None)
    assert auth_basic( { 'AUTHORIZATION': 'Basic QWxhZGRpbjpPcGVuU2VzYW1l' }) == ('Aladdin', 'OpenSesame')
    assert auth_basic( { 'HTTP_AUTHORIZATION': 'Basic QWxhZGRpbjpPcGVuU2VzYW1l' }) == ('Aladdin', 'OpenSesame')

def auth_required(fn):
    def _(req):
        username, password = auth_basic(req.env)
        if username is None:
            return http_auth_needed(CFG.realm)
        cnt = db_rows(''' select * from users where username = ? and password = ? ''',
            (username, auth_password(password)))
        if len(cnt) == 0:
            return http_auth_needed(CFG.realm)
        req.user = username
        return fn(req)
    return _

def http_auth_needed(realm):
    return '401 Unauthorized', [('WWW-Authenticate', 'Basic realm="{}"'.format(realm))], None

def http_redirect(dst):
    return '301 Redirect', [('Location', dst)], None

def http_ok(ret):
    return '200 OK', [('Content-type', 'text/html')], str(ret)

def http_ok_json(ret):
    return '200 OK', [('Content-type', 'application/json')], json.dumps(ret)

class RequestEnviron:
    def __init__(self, env):
        self.user, self.input, self.rowid, self.env = None, None, None, env

def route(req):
    for meth,rt,fn in CFG.routes:
        m = rt.match(req.env['PATH_INFO'])
        if m and req.env['REQUEST_METHOD'] == meth:
            if len(m.groups()) > 0:
                req.rowid = m[1]
            return fn(req)
    return http_ok('UNSUPPORTED ROUTE')

def request_handler(env, start_response):
    req = RequestEnviron(env)
    if 'CONTENT_LENGTH' in env and env['CONTENT_LENGTH'] != '':
        l = int(env['CONTENT_LENGTH'])
        c = env['wsgi.input'].read(l)
        req.input = json.loads(c)
    status, headers, ret = route(req)
    start_response(status, headers)
    if ret is None:
        return [b'']
    return [str.encode(ret)]

def generic_new_(table):
    def _(req):
        req.rowid = db_exec(' insert into ' + table + ' default values ')
        return generic_set_(table)(req)
    return auth_required(_)

def generic_get_(table):
    def _(req):
        return http_ok_json( db_rows(''' select * from decisions where rowid = ? ''', (req.rowid,)) )
    return auth_required(_)

def generic_set_(table):
    def _(req):
        query = ' update ' + table + ' set owner = ? '
        values = [req.user]
        for k,v in req.input.items():
            query += ', ' + sql_safe(k) + ' = ? '
            values.append( v )
        query += ' where rowid = ?'
        values.append(req.rowid)
        db_exec(query, values)
        return http_ok('')
    return auth_required(_)

def generic_del_(table):
    def _(req):
        return http_ok(db_exec('delete from ' + table + ' where rowid = ?', (req.rowid,)))
    return auth_required(_)

def generic_list_(table):
    def _(req):
        return http_ok_json(db_rows(' select rowid, * from ' + table + ' where owner = ?', (req.user,) ))
    return auth_required(_)


def run(realm="Local", port=5555, prefix='^/resty', database='resty.db', exposed_tables=None, functions=None):
    ''' setup routes, then run as wsgi '''
    routes = []
    for t in exposed_tables:
        routes += [
        ('GET',    prefix + '/' + t + '$', generic_list_(t) ),
        ('HEAD',   prefix + '/' + t + '$', generic_list_(t) ),
        ('POST',   prefix + '/' + t + '$', generic_new_(t) ),
        ('GET',    prefix + '/' + t + '/([0-9]+)$', generic_get_(t) ),
        ('HEAD',   prefix + '/' + t + '/([0-9]+)$', generic_get_(t) ),
        ('POST',   prefix + '/' + t + '/([0-9]+)$', generic_set_(t) ),
        ('DELETE', prefix + '/' + t + '/([0-9]+)$', generic_del_(t) ) ]

    fns = { k:v for k,v in functions.items() if callable(v) }
    routes += [ ('GET',    prefix + '/' + k[:-5] + '$', v)          for k,v in fns.items() if k.endswith('_list') ]
    routes += [ ('HEAD',   prefix + '/' + k[:-5] + '$', v)          for k,v in fns.items() if k.endswith('_list') ]
    routes += [ ('POST',   prefix + '/' + k[:-4] + '$', v)          for k,v in fns.items() if k.endswith('_new') ]
    routes += [ ('GET',    prefix + '/' + k[:-4] + '/([0-9]+)$', v) for k,v in fns.items() if k.endswith('_get') ]
    routes += [ ('HEAD',   prefix + '/' + k[:-4] + '/([0-9]+)$', v) for k,v in fns.items() if k.endswith('_get') ]
    routes += [ ('POST',   prefix + '/' + k[:-4] + '/([0-9]+)$', v) for k,v in fns.items() if k.endswith('_set') ]
    routes += [ ('DELETE', prefix + '/' + k[:-4] + '/([0-9]+)$', v) for k,v in fns.items() if k.endswith('_del') ]
    for a,b,c in sorted(routes, key=lambda x: x[1]):
        debug('{:10s} {}'.format(a,b))
    routes =  [ (a, re.compile(b),c) for a,b,c in routes ]

    global CFG
    CFG = namedtuple('Config',
        'realm port   database   routes')(
        realm, port,  database,  routes)

    for k,v in fns.items():
        if k.endswith('_setup'):
            v()

    try:
        wsgiref.simple_server.make_server('', port, request_handler).serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    for f in [ v for k,v in globals().items() if k.startswith('test_') ]:
        f()
