import os


@app.route("/owned/<command>")
@owns_resource("job")
def owned(command):
    os.system(command)


@app.route("/authenticated/<command>")
@login_required
def authenticated(command):
    os.system(command)
